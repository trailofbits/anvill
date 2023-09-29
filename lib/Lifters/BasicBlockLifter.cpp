#include "BasicBlockLifter.h"

#include <anvill/Type.h>
#include <anvill/Utils.h>
#include <glog/logging.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/Util.h>

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <iterator>
#include <memory>
#include <vector>

#include "Lifters/CodeLifter.h"
#include "Lifters/FunctionLifter.h"
#include "anvill/Declarations.h"
#include "anvill/Optimize.h"

namespace anvill {

void BasicBlockLifter::LiftBasicBlockFunction() {
  auto bbfunc = this->CreateBasicBlockFunction();
  this->LiftInstructionsIntoLiftedFunction();
  DCHECK(!llvm::verifyFunction(*this->lifted_func, &llvm::errs()));
  DCHECK(!llvm::verifyFunction(*bbfunc.func, &llvm::errs()));

  this->RecursivelyInlineFunctionCallees(bbfunc.func);
}


remill::DecodingContext BasicBlockLifter::ApplyContextAssignments(
    const std::unordered_map<std::string, uint64_t> &assignments,
    remill::DecodingContext prev_context) {
  for (const auto &[k, v] : assignments) {
    prev_context.UpdateContextReg(k, v);
  }
  return prev_context;
}


llvm::CallInst *BasicBlockLifter::AddCallFromBasicBlockFunctionToLifted(
    llvm::BasicBlock *source_block, llvm::Function *dest_func,
    const remill::IntrinsicTable &intrinsics, llvm::Value *pc_hint) {
  auto func = source_block->getParent();
  llvm::IRBuilder<> ir(source_block);
  std::array<llvm::Value *, remill::kNumBlockArgs> args;
  args[remill::kMemoryPointerArgNum] =
      NthArgument(func, remill::kMemoryPointerArgNum);
  args[remill::kStatePointerArgNum] =
      NthArgument(func, remill::kStatePointerArgNum);

  if (pc_hint) {
    args[remill::kPCArgNum] = pc_hint;
  } else {
    args[remill::kPCArgNum] =
        remill::LoadNextProgramCounter(source_block, this->intrinsics);
  }

  return ir.CreateCall(dest_func, args);
}


// Helper to figure out the address where execution will resume after a
// function call. In practice this is the instruction following the function
// call, encoded in `inst.branch_not_taken_pc`. However, SPARC has a terrible
// ABI where they inject an invalid instruction following some calls as a way
// of communicating to the callee that they should return an object of a
// particular, hard-coded size. Thus, we want to actually identify then ignore
// that instruction, and present the following address for where execution
// should resume after a `call`.
std::pair<uint64_t, llvm::Value *>
BasicBlockLifter::LoadFunctionReturnAddress(const remill::Instruction &inst,
                                            llvm::BasicBlock *block) {

  const auto pc = inst.branch_not_taken_pc;

  // The semantics for handling a call save the expected return program counter
  // into a local variable.
  auto ret_pc = this->op_lifter->LoadRegValue(block, state_ptr,
                                              remill::kReturnPCVariableName);
  if (!is_sparc) {
    return {pc, ret_pc};
  }

  uint8_t bytes[4] = {};

  for (auto i = 0u; i < 4u; ++i) {
    auto [byte, accessible, perms] = memory_provider.Query(pc + i);
    switch (accessible) {
      case ByteAvailability::kUnknown:
      case ByteAvailability::kUnavailable:
        LOG(ERROR)
            << "Byte at address " << std::hex << (pc + i)
            << " is not available for inspection to figure out return address "
            << " of call instruction at address " << pc << std::dec;
        return {pc, ret_pc};

      default: bytes[i] = byte; break;
    }

    switch (perms) {
      case BytePermission::kUnknown:
      case BytePermission::kReadableExecutable:
      case BytePermission::kReadableWritableExecutable: break;
      case BytePermission::kReadable:
      case BytePermission::kReadableWritable:
        LOG(ERROR)
            << "Byte at address " << std::hex << (pc + i) << " being inspected "
            << "to figure out return address of call instruction at address "
            << pc << " is not executable" << std::dec;
        return {pc, ret_pc};
    }
  }

  union Format0a {
    uint32_t flat;
    struct {
      uint32_t imm22 : 22;
      uint32_t op2 : 3;
      uint32_t rd : 5;
      uint32_t op : 2;
    } u __attribute__((packed));
  } __attribute__((packed)) enc = {};
  static_assert(sizeof(Format0a) == 4, " ");

  enc.flat |= bytes[0];
  enc.flat <<= 8;
  enc.flat |= bytes[1];
  enc.flat <<= 8;
  enc.flat |= bytes[2];
  enc.flat <<= 8;
  enc.flat |= bytes[3];

  // This looks like an `unimp <imm22>` instruction, where the `imm22` encodes
  // the size of the value to return. See "Specificationming Note" in v8 manual,
  // B.31, p 137.
  //
  // TODO(pag, kumarak): Does a zero value in `enc.u.imm22` imply a no-return
  //                     function? Try this on Compiler Explorer!
  if (!enc.u.op && !enc.u.op2) {
    DLOG(INFO) << "Found structure return of size " << enc.u.imm22 << " to "
               << std::hex << pc << " at " << inst.pc << std::dec;

    llvm::IRBuilder<> ir(block);
    return {pc + 4u,
            ir.CreateAdd(ret_pc, llvm::ConstantInt::get(ret_pc->getType(), 4))};

  } else {
    return {pc, ret_pc};
  }
}


bool BasicBlockLifter::DoInterProceduralControlFlow(
    const remill::Instruction &insn, llvm::BasicBlock *block,
    const anvill::ControlFlowOverride &override) {
  // only handle inter-proc since intra-proc are handled implicitly by the CFG.
  llvm::IRBuilder<> builder(block);
  if (std::holds_alternative<anvill::Call>(override)) {

    auto cc = std::get<anvill::Call>(override);

    llvm::CallInst *call = nullptr;
    if (cc.target_address.has_value()) {
      call = this->AddCallFromBasicBlockFunctionToLifted(
          block, this->intrinsics.function_call, this->intrinsics,
          this->options.program_counter_init_procedure(
              builder, this->address_type, *cc.target_address));
    } else {
      call = this->AddCallFromBasicBlockFunctionToLifted(
          block, this->intrinsics.function_call, this->intrinsics);
    }
    if (!cc.stop) {
      auto [_, raddr] = this->LoadFunctionReturnAddress(insn, block);
      auto npc = remill::LoadNextProgramCounterRef(block);
      auto pc = remill::LoadProgramCounterRef(block);
      builder.CreateStore(raddr, npc);
      builder.CreateStore(raddr, pc);
    } else {
      call->setDoesNotReturn();

      remill::AddTerminatingTailCall(block, intrinsics.error, intrinsics);
    }
    return !cc.stop;
  } else if (std::holds_alternative<anvill::Return>(override)) {
    auto func = block->getParent();
    auto should_return = func->getArg(kShouldReturnArgNum);
    builder.CreateStore(llvm::Constant::getAllOnesValue(
                            llvm::IntegerType::getInt1Ty(llvm_context)),
                        should_return);
  }

  return true;
}


bool BasicBlockLifter::ApplyInterProceduralControlFlowOverride(
    const remill::Instruction &insn, llvm::BasicBlock *&block) {


  // if this instruction is conditional and interprocedural then we are going to split the block into a case were we do take it and a branch where we dont and then rejoin

  auto override = options.control_flow_provider.GetControlFlowOverride(insn.pc);

  if ((std::holds_alternative<anvill::Call>(override) ||
       std::holds_alternative<anvill::Return>(override))) {
    if (std::holds_alternative<remill::Instruction::ConditionalInstruction>(
            insn.flows)) {
      auto btaken = remill::LoadBranchTaken(block);
      llvm::IRBuilder<> builder(block);
      auto do_control_flow =
          llvm::BasicBlock::Create(block->getContext(), "", block->getParent());
      auto continuation =
          llvm::BasicBlock::Create(block->getContext(), "", block->getParent());
      builder.CreateCondBr(btaken, do_control_flow, continuation);

      // if the interprocedural control flow block isnt terminal link it back up
      if (this->DoInterProceduralControlFlow(insn, do_control_flow, override)) {
        llvm::BranchInst::Create(continuation, do_control_flow);
      }

      block = continuation;
      return true;
    } else {
      return this->DoInterProceduralControlFlow(insn, block, override);
    }
  }

  return true;
}

remill::DecodingContext
BasicBlockLifter::CreateDecodingContext(const CodeBlock &blk) {
  auto init_context = this->options.arch->CreateInitialContext();
  return this->ApplyContextAssignments(blk.context_assignments,
                                       std::move(init_context));
}

// Try to decode an instruction at address `addr` into `*inst_out`. Returns
// the context map of the decoded instruction if successful and std::nullopt otherwise. `is_delayed` tells the decoder
// whether or not the instruction being decoded is being decoded inside of a
// delay slot of another instruction.
bool BasicBlockLifter::DecodeInstructionInto(const uint64_t addr,
                                             bool is_delayed,
                                             remill::Instruction *inst_out,
                                             remill::DecodingContext context) {
  static const auto max_inst_size = options.arch->MaxInstructionSize(context);
  inst_out->Reset();

  // Read the maximum number of bytes possible for instructions on this
  // architecture. For x86(-64), this is 15 bytes, whereas for fixed-width
  // architectures like AArch32/AArch64 and SPARC32/SPARC64, this is 4 bytes.
  inst_out->bytes.reserve(max_inst_size);

  auto accumulate_inst_byte = [=](auto byte, auto accessible, auto perms) {
    switch (accessible) {
      case ByteAvailability::kUnknown:
      case ByteAvailability::kUnavailable: return false;
      default:
        switch (perms) {
          case BytePermission::kUnknown:
          case BytePermission::kReadableExecutable:
          case BytePermission::kReadableWritableExecutable:
            inst_out->bytes.push_back(static_cast<char>(byte));
            return true;
          case BytePermission::kReadable:
          case BytePermission::kReadableWritable: return false;
        }
    }
  };

  for (auto i = 0u; i < max_inst_size; ++i) {
    if (!std::apply(accumulate_inst_byte, memory_provider.Query(addr + i))) {
      break;
    }
  }

  if (is_delayed) {
    return options.arch->DecodeDelayedInstruction(
        addr, inst_out->bytes, *inst_out, std::move(context));
  } else {
    return options.arch->DecodeInstruction(addr, inst_out->bytes, *inst_out,
                                           std::move(context));
  }
}


void BasicBlockLifter::ApplyTypeHint(llvm::IRBuilder<> &bldr,
                                     const ValueDecl &type_hint) {

  auto ty_hint = this->GetTypeHintFunction();
  auto state_ptr_internal =
      this->lifted_func->getArg(remill::kStatePointerArgNum);
  auto mem_ptr =
      remill::LoadMemoryPointer(bldr.GetInsertBlock(), this->intrinsics);
  auto curr_value =
      anvill::LoadLiftedValue(type_hint, options.TypeDictionary(), intrinsics,
                              options.arch, bldr, state_ptr_internal, mem_ptr);

  if (curr_value->getType()->isPointerTy()) {
    auto call = bldr.CreateCall(ty_hint, {curr_value});
    call->setMetadata("anvill.type", this->type_specifier.EncodeToMetadata(
                                         type_hint.spec_type));
    curr_value = call;
  }

  auto new_mem_ptr =
      StoreNativeValue(curr_value, type_hint, options.TypeDictionary(),
                       intrinsics, bldr, state_ptr_internal, mem_ptr);
  bldr.CreateStore(new_mem_ptr,
                   remill::LoadMemoryPointerRef(bldr.GetInsertBlock()));
}


void BasicBlockLifter::LiftInstructionsIntoLiftedFunction() {
  auto entry_block = &this->lifted_func->getEntryBlock();

  auto bb = llvm::BasicBlock::Create(this->lifted_func->getContext(), "",
                                     this->lifted_func);


  llvm::BranchInst::Create(bb, entry_block);

  remill::Instruction inst;

  auto reached_addr = this->block_def.addr;
  // TODO(Ian): use a different context

  auto init_context = this->CreateDecodingContext(this->block_def);

  DLOG(INFO) << "Decoding block at addr: " << std::hex << this->block_def.addr
             << " with size " << this->block_def.size;
  bool ended_on_terminal = false;
  while (reached_addr < this->block_def.addr + this->block_def.size &&
         !ended_on_terminal) {
    auto addr = reached_addr;
    DLOG(INFO) << "Decoding at addr " << std::hex << addr;
    auto res = this->DecodeInstructionInto(addr, false, &inst, init_context);
    if (!res) {
      remill::AddTerminatingTailCall(bb, this->intrinsics.error,
                                     this->intrinsics);
      LOG(ERROR) << "Failed to decode insn in block " << std::hex << addr;
      return;
    }

    reached_addr += inst.bytes.size();

    // Even when something isn't supported or is invalid, we still lift
    // a call to a semantic, e.g.`INVALID_INSTRUCTION`, so we really want
    // to treat instruction lifting as an operation that can't fail.


    std::ignore = inst.GetLifter()->LiftIntoBlock(
        inst, bb, this->lifted_func->getArg(remill::kStatePointerArgNum),
        false /* is_delayed */);

    llvm::IRBuilder<> builder(bb);

    auto start =
        std::lower_bound(decl.type_hints.begin(), decl.type_hints.end(),
                         inst.pc, [](const TypeHint &hint_rhs, uint64_t addr) {
                           return hint_rhs.target_addr < addr;
                         });
    auto end =
        std::upper_bound(decl.type_hints.begin(), decl.type_hints.end(),
                         inst.pc, [](uint64_t addr, const TypeHint &hint_rhs) {
                           return addr < hint_rhs.target_addr;
                         });
    for (; start != end; start++) {
      this->ApplyTypeHint(builder, start->hint);
    }

    ended_on_terminal =
        !this->ApplyInterProceduralControlFlowOverride(inst, bb);
    DLOG_IF(INFO, ended_on_terminal)
        << "On terminal at addr: " << std::hex << addr;
  }

  if (!ended_on_terminal) {
    llvm::IRBuilder<> builder(bb);

    builder.CreateStore(remill::LoadNextProgramCounter(bb, this->intrinsics),
                        this->lifted_func->getArg(kNextPCArgNum));


    llvm::ReturnInst::Create(
        bb->getContext(), remill::LoadMemoryPointer(bb, this->intrinsics), bb);
  }
}


llvm::MDNode *BasicBlockLifter::GetBasicBlockAddrAnnotation(uint64_t addr) const {
  return this->GetAddrAnnotation(addr, this->semantics_module->getContext());
}
llvm::MDNode *BasicBlockLifter::GetBasicBlockUidAnnotation(Uid uid) const {
  return this->GetUidAnnotation(uid, this->semantics_module->getContext());
}

llvm::Function *BasicBlockLifter::DeclareBasicBlockFunction() {
  std::string name_ = "func" + std::to_string(decl.address) + "basic_block" +
                      std::to_string(this->block_def.addr) + "_" + std::to_string(this->block_def.uid.value);
  auto &context = this->semantics_module->getContext();
  llvm::FunctionType *lifted_func_type =
      llvm::dyn_cast<llvm::FunctionType>(remill::RecontextualizeType(
          this->options.arch->LiftedFunctionType(), context));

  std::vector<llvm::Type *> params = std::vector(
      lifted_func_type->param_begin(), lifted_func_type->param_end());

  // pointer to state pointer
  params[remill::kStatePointerArgNum] = llvm::PointerType::get(context, 0);


  for (size_t i = 0; i < this->var_struct_ty->getNumElements(); i++) {
    // pointer to each param
    params.push_back(llvm::PointerType::get(context, 0));
  }

  auto ret_type = this->block_context->ReturnValue();
  llvm::FunctionType *func_type = llvm::FunctionType::get(
      this->flifter.curr_decl->type->getReturnType(), params, false);

  llvm::StringRef name(name_.data(), name_.size());
  return llvm::Function::Create(func_type, llvm::GlobalValue::ExternalLinkage,
                                0u, name, this->semantics_module);
}

BasicBlockFunction BasicBlockLifter::CreateBasicBlockFunction() {
  auto func = bb_func;
  func->setMetadata(anvill::kBasicBlockAddrMetadata,
                    GetBasicBlockAddrAnnotation(this->block_def.addr));
  func->setMetadata(anvill::kBasicBlockUidMetadata,
                    GetBasicBlockUidAnnotation(this->block_def.uid));

  auto &context = this->semantics_module->getContext();
  llvm::FunctionType *lifted_func_type =
      llvm::dyn_cast<llvm::FunctionType>(remill::RecontextualizeType(
          this->options.arch->LiftedFunctionType(), context));
  auto start_ind = lifted_func_type->getNumParams();
  for (auto var : decl.in_scope_variables) {
    auto arg = remill::NthArgument(func, start_ind);
    if (!var.name.empty()) {
      arg->setName(var.name);
    }

    if (std::all_of(var.oredered_locs.begin(), var.oredered_locs.end(),
                    [](const LowLoc &loc) -> bool { return loc.reg; })) {
      // Registers should not have aliases, or be captured
      arg->addAttr(llvm::Attribute::get(llvm_context,
                                        llvm::Attribute::AttrKind::NoAlias));
      arg->addAttr(llvm::Attribute::get(llvm_context,
                                        llvm::Attribute::AttrKind::NoCapture));
    }

    start_ind += 1;
  }

  auto memory = remill::NthArgument(func, remill::kMemoryPointerArgNum);
  auto state = remill::NthArgument(func, remill::kStatePointerArgNum);
  auto pc = remill::NthArgument(func, remill::kPCArgNum);

  memory->setName("memory");
  memory->addAttr(
      llvm::Attribute::get(llvm_context, llvm::Attribute::AttrKind::NoAlias));
  memory->addAttr(
      llvm::Attribute::get(llvm_context, llvm::Attribute::AttrKind::NoCapture));
  pc->setName("program_counter");
  state->setName("stack");


  auto liftedty = this->options.arch->LiftedFunctionType();

  std::vector<llvm::Type *> new_params;
  new_params.reserve(liftedty->getNumParams() + 2);

  for (auto param : liftedty->params()) {
    new_params.push_back(param);
  }
  auto ptr_ty = llvm::PointerType::get(context, 0);
  new_params.push_back(ptr_ty);
  new_params.push_back(ptr_ty);


  llvm::FunctionType *new_func_type = llvm::FunctionType::get(
      lifted_func_type->getReturnType(), new_params, false);


  this->lifted_func = llvm::Function::Create(
      new_func_type, llvm::GlobalValue::ExternalLinkage, 0u,
      func->getName() + "lowlift", this->semantics_module);

  options.arch->InitializeEmptyLiftedFunction(this->lifted_func);


  llvm::BasicBlock::Create(context, "", func);
  auto &blk = func->getEntryBlock();
  llvm::IRBuilder<> ir(&blk);
  auto next_pc = ir.CreateAlloca(llvm::IntegerType::getInt64Ty(context),
                                 nullptr, "next_pc");
  auto should_return = ir.CreateAlloca(llvm::IntegerType::getInt1Ty(context),
                                       nullptr, "should_return");
  ir.CreateStore(llvm::ConstantInt::getFalse(context), should_return);
  auto lded_mem =
      ir.CreateLoad(llvm::PointerType::get(this->llvm_context, 0), memory);

  ir.CreateStore(lded_mem,
                 ir.CreateAlloca(llvm::PointerType::get(this->llvm_context, 0),
                                 nullptr, "MEMORY"));

  this->state_ptr =
      this->AllocateAndInitializeStateStructure(&blk, options.arch);

  // Put registers that are referencing the stack in terms of their displacement so that we
  // Can resolve these stack references later .

  auto sp_value =
      options.stack_pointer_init_procedure(ir, sp_reg, this->block_def.addr);
  auto sp_ptr = sp_reg->AddressOf(this->state_ptr, ir);
  // Initialize the stack pointer.
  ir.CreateStore(sp_value, sp_ptr);

  auto stack_offsets = this->block_context->GetStackOffsetsAtEntry();
  for (auto &reg_off : stack_offsets.affine_equalities) {
    auto new_value = LifterOptions::SymbolicStackPointerInitWithOffset(
        ir, this->sp_reg, this->block_def.addr, reg_off.stack_offset);
    auto nmem = StoreNativeValue(
        new_value, reg_off.target_value, type_provider.Dictionary(), intrinsics,
        ir, this->state_ptr, remill::LoadMemoryPointer(ir, intrinsics));
    ir.CreateStore(nmem, remill::LoadMemoryPointerRef(ir.GetInsertBlock()));
  }

  PointerProvider ptr_provider =
      [this, func](const ParameterDecl &param) -> llvm::Value * {
    return this->block_context->ProvidePointerFromFunctionArgs(func, param);
  };

  DLOG(INFO) << "Live values at entry to function "
             << this->block_context->LiveBBParamsAtEntry().size();
  this->UnpackLiveValues(ir, ptr_provider, this->state_ptr,
                         this->block_context->LiveBBParamsAtEntry());

  for (auto &reg_const : block_context->GetConstantsAtEntry()) {
    llvm::Value *new_value = nullptr;
    llvm::Type *target_type = reg_const.target_value.type;
    if (reg_const.should_taint_by_pc) {
      new_value = this->options.program_counter_init_procedure(
          ir, this->address_type, reg_const.value);

      if (this->address_type != target_type) {
        new_value = AdaptToType(ir, new_value, target_type);
      }
    } else {
      new_value = llvm::ConstantInt::get(target_type, reg_const.value, false);
    }


    //DLOG_IF(INFO, reg_const.target_value.reg)
    //    << "Dumping " << reg_const.target_value.reg->name << " " << std::hex
    //    << reg_const.value;
    auto nmem = StoreNativeValue(new_value, reg_const.target_value,
                                 type_provider.Dictionary(), intrinsics, ir,
                                 this->state_ptr,
                                 remill::LoadMemoryPointer(ir, intrinsics));
    ir.CreateStore(nmem, remill::LoadMemoryPointerRef(ir.GetInsertBlock()));
  }

  auto pc_arg = remill::NthArgument(func, remill::kPCArgNum);
  auto mem_arg = remill::NthArgument(func, remill::kMemoryPointerArgNum);

  func->addFnAttr(llvm::Attribute::NoInline);
  //func->setLinkage(llvm::GlobalValue::InternalLinkage);

  auto mem_res = remill::LoadMemoryPointer(ir, this->intrinsics);

  // Initialize the program counter
  auto pc_ptr = pc_reg->AddressOf(this->state_ptr, ir);
  auto pc_val = this->options.program_counter_init_procedure(
      ir, this->address_type, this->block_def.addr);
  ir.CreateStore(pc_val, pc_ptr);

  std::array<llvm::Value *, kNumLiftedBasicBlockArgs> args = {
      this->state_ptr, pc_val, mem_res, next_pc, should_return};

  auto ret_mem = ir.CreateCall(this->lifted_func, args);

  this->PackLiveValues(ir, this->state_ptr, ptr_provider,
                       this->block_context->LiveBBParamsAtExit());


  CHECK(ir.GetInsertPoint() == func->getEntryBlock().end());

  BasicBlockFunction bbf{func, pc_arg, mem_arg, next_pc, state};


  ir.CreateStore(ret_mem, memory);
  ir.CreateStore(ret_mem, remill::LoadMemoryPointerRef(ir.GetInsertBlock()));
  TerminateBasicBlockFunction(func, ir, ret_mem, should_return, bbf);

  return bbf;
}

// Setup the returns for this function we tail call all successors
void BasicBlockLifter::TerminateBasicBlockFunction(
    llvm::Function *caller, llvm::IRBuilder<> &ir, llvm::Value *next_mem,
    llvm::Value *should_return, const BasicBlockFunction &bbfunc) {
  auto &context = this->bb_func->getContext();
  this->invalid_successor_block =
      llvm::BasicBlock::Create(context, "invalid_successor", this->bb_func);
  auto jump_block = llvm::BasicBlock::Create(context, "", this->bb_func);
  auto ret_block = llvm::BasicBlock::Create(context, "", this->bb_func);

  // TODO(Ian): maybe want to call remill_error here
  new llvm::UnreachableInst(next_mem->getContext(),
                            this->invalid_successor_block);

  auto should_return_value =
      ir.CreateLoad(llvm::IntegerType::getInt1Ty(context), should_return);
  ir.CreateCondBr(should_return_value, ret_block, jump_block);

  ir.SetInsertPoint(jump_block);
  auto pc = ir.CreateLoad(address_type, bbfunc.next_pc_out);
  auto sw = ir.CreateSwitch(pc, this->invalid_successor_block);

  for (auto edge_uid : this->block_def.outgoing_edges) {
    auto calling_bb =
        llvm::BasicBlock::Create(next_mem->getContext(), "", bbfunc.func);
    llvm::IRBuilder<> calling_bb_builder(calling_bb);
    auto edge_bb = this->decl.cfg.at(edge_uid);
    auto &child_lifter = this->flifter.GetOrCreateBasicBlockLifter(edge_bb.uid);
    auto retval = child_lifter.ControlFlowCallBasicBlockFunction(
        caller, calling_bb_builder, this->state_ptr, bbfunc.stack, next_mem);
    if (this->flifter.curr_decl->type->getReturnType()->isVoidTy()) {
      calling_bb_builder.CreateRetVoid();
    } else {
      calling_bb_builder.CreateRet(retval);
    }

    auto succ_const = llvm::ConstantInt::get(
        llvm::cast<llvm::IntegerType>(this->address_type), edge_bb.addr);
    sw->addCase(succ_const, calling_bb);
  }

  ir.SetInsertPoint(ret_block);
  if (this->flifter.curr_decl->type->getReturnType()->isVoidTy()) {
    ir.CreateRetVoid();
  } else {
    auto retval = anvill::LoadLiftedValue(
        block_context->ReturnValue(), options.TypeDictionary(), intrinsics,
        options.arch, ir, this->state_ptr, next_mem);
    ir.CreateRet(retval);
  }
}

llvm::StructType *BasicBlockLifter::StructTypeFromVars() const {
  std::vector<llvm::Type *> field_types;
  std::transform(decl.in_scope_variables.begin(), decl.in_scope_variables.end(),
                 std::back_inserter(field_types),
                 [](auto &param) { return param.type; });

  return llvm::StructType::get(llvm_context, field_types,
                               "sty_for_basic_block_function");
}

// Packs in scope variables into a struct
void BasicBlockLifter::PackLiveValues(
    llvm::IRBuilder<> &bldr, llvm::Value *from_state_ptr,
    PointerProvider into_vars,
    const std::vector<BasicBlockVariable> &decls) const {

  for (auto decl : decls) {

    if (!HasMemLoc(decl.param)) {
      auto ptr = into_vars(decl.param);

      auto state_loaded_value = LoadLiftedValue(
          decl.param, this->type_provider.Dictionary(), this->intrinsics,
          this->options.arch, bldr, from_state_ptr,
          remill::LoadMemoryPointer(bldr, this->intrinsics));

      bldr.CreateStore(state_loaded_value, ptr);
    } else {
      // TODO(Ian): The assumption is we dont have live values split between the stack and a register for now...
      // Maybe at some point we can just go ahead and store everything
      CHECK(!HasRegLoc(decl.param));
    }
  }
}


void BasicBlockLifter::UnpackLiveValues(
    llvm::IRBuilder<> &bldr, PointerProvider returned_value,
    llvm::Value *into_state_ptr,
    const std::vector<BasicBlockVariable> &decls) const {
  auto blk = bldr.GetInsertBlock();

  for (auto decl : decls) {
    // is this how we want to do this.... now the value really doesnt live in memory anywhere but the frame.
    if (!HasMemLoc(decl.param)) {
      auto ptr = returned_value(decl.param);
      auto loaded_var_val =
          bldr.CreateLoad(decl.param.type, ptr, decl.param.name);
      loaded_var_val->setMetadata(
          "anvill.type",
          this->type_specifier.EncodeToMetadata(decl.param.spec_type));

      auto mem_ptr = remill::LoadMemoryPointer(bldr, this->intrinsics);
      auto new_mem_ptr = StoreNativeValue(
          loaded_var_val, decl.param, this->type_provider.Dictionary(),
          this->intrinsics, bldr, into_state_ptr, mem_ptr);
      bldr.SetInsertPoint(bldr.GetInsertBlock());

      bldr.CreateStore(new_mem_ptr,
                       remill::LoadMemoryPointerRef(bldr.GetInsertBlock()));
    } else {
      // TODO(Ian): The assumption is we dont have live values split between the stack and a register for now...
      // Maybe at some point we can just go ahead and store everything
      CHECK(!HasRegLoc(decl.param));
    }
  }
  CHECK(bldr.GetInsertPoint() == blk->end());
}

// TODO(Ian): dependent on calling context we need fetch the memory and next program counter
// ref either from the args or from the parent func state
llvm::CallInst *BasicBlockLifter::CallBasicBlockFunction(
    llvm::IRBuilder<> &builder, llvm::Value *parent_state,
    llvm::Value *parent_stack, llvm::Value *memory_pointer) const {

  std::vector<llvm::Value *> args(remill::kNumBlockArgs);
  auto out_param_locals = builder.CreateAlloca(this->var_struct_ty);
  args[0] = parent_stack;

  args[remill::kPCArgNum] = options.program_counter_init_procedure(
      builder, this->address_type, block_def.addr);
  args[remill::kMemoryPointerArgNum] = memory_pointer;

  AbstractStack stack(
      builder.getContext(), {{decl.maximum_depth, parent_stack}},
      this->options.stack_frame_recovery_options.stack_grows_down,
      decl.GetPointerDisplacement());
  PointerProvider ptr_provider =
      [&builder, this, out_param_locals,
       &stack](const ParameterDecl &repr_var) -> llvm::Value * {
    DLOG(INFO) << "Lifting: " << repr_var.name << " for call";
    if (HasMemLoc(repr_var)) {
      // TODO(Ian): the assumption here since we are able to build a single pointer here into the frame is that
      // svars are single valuedecl contigous
      CHECK(repr_var.oredered_locs.size() == 1);
      auto stack_ptr = stack.PointerToStackMemberFromOffset(
          builder, repr_var.oredered_locs[0].mem_offset);
      if (stack_ptr) {
        return *stack_ptr;
      } else {
        LOG(FATAL)
            << "Unable to create a ptr to the stack, the stack is too small to represent the param.";
      }
    }

    // ok so this should be provide pointer from args in a way
    // stack probably shouldnt be passed at all, if we dont have a loc
    // then it's not live
    return block_context->ProvidePointerFromStruct(builder, var_struct_ty,
                                                   out_param_locals, repr_var);
  };

  this->PackLiveValues(builder, parent_state, ptr_provider,
                       this->block_context->LiveBBParamsAtEntry());

  for (auto &param : block_context->GetParams()) {
    auto ptr = ptr_provider(param);
    CHECK(ptr != nullptr);
    args.push_back(ptr);
  }

  auto retval = builder.CreateCall(bb_func, args);
  retval->setTailCall(true);

  return retval;
}

llvm::CallInst *BasicBlockLifter::ControlFlowCallBasicBlockFunction(
    llvm::Function *caller, llvm::IRBuilder<> &builder,
    llvm::Value *parent_state, llvm::Value *parent_stack,
    llvm::Value *memory_pointer) const {

  std::vector<llvm::Value *> args;
  std::transform(caller->arg_begin(), caller->arg_end(),
                 std::back_inserter(args),
                 [](llvm::Argument &arg) -> llvm::Value * { return &arg; });

  auto retval = builder.CreateCall(bb_func, args);
  retval->setTailCall(true);

  return retval;
}

BasicBlockLifter::BasicBlockLifter(
    std::unique_ptr<BasicBlockContext> block_context, const FunctionDecl &decl,
    CodeBlock block_def, const LifterOptions &options_,
    llvm::Module *semantics_module, const TypeTranslator &type_specifier,
    FunctionLifter &flifter)
    : CodeLifter(options_, semantics_module, type_specifier),
      block_context(std::move(block_context)),
      block_def(std::move(block_def)),
      decl(decl),
      flifter(flifter) {
  this->var_struct_ty = this->StructTypeFromVars();
  this->bb_func = this->DeclareBasicBlockFunction();
}

CallableBasicBlockFunction::CallableBasicBlockFunction(
    llvm::Function *func, CodeBlock block, BasicBlockLifter bb_lifter)
    : func(func),
      block(block),
      bb_lifter(std::move(bb_lifter)) {}


const CodeBlock &CallableBasicBlockFunction::GetBlock() const {
  return this->block;
}

llvm::Function *CallableBasicBlockFunction::GetFunction() const {
  return this->func;
}

}  // namespace anvill
