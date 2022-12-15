#include "BasicBlockLifter.h"

#include <anvill/Type.h>
#include <anvill/Utils.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/Util.h>

#include <algorithm>
#include <iterator>
#include <memory>
#include <vector>

#include "Lifters/CodeLifter.h"
#include "anvill/Declarations.h"
#include "anvill/Optimize.h"

namespace anvill {

CallableBasicBlockFunction BasicBlockLifter::LiftBasicBlockFunction() && {
  auto bbfunc = this->CreateBasicBlockFunction();
  this->LiftInstructionsIntoLiftedFunction();
  CHECK(!llvm::verifyFunction(*this->lifted_func, &llvm::errs()));
  CHECK(!llvm::verifyFunction(*bbfunc.func, &llvm::errs()));

  this->RecursivelyInlineFunctionCallees(bbfunc.func);
  anvill::EntityLifter lifter(options);

  return CallableBasicBlockFunction(bbfunc.func,
                                    this->block_context.GetAvailableVariables(),
                                    block_def, std::move(*this));
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
    LOG(INFO) << "Found structure return of size " << enc.u.imm22 << " to "
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

    if (cc.target_address.has_value()) {
      this->AddCallFromBasicBlockFunctionToLifted(
          block, this->intrinsics.function_call, this->intrinsics,
          this->options.program_counter_init_procedure(builder, this->pc_reg,
                                                       *cc.target_address));
    } else {
      this->AddCallFromBasicBlockFunctionToLifted(
          block, this->intrinsics.function_call, this->intrinsics);
    }
    if (!cc.stop) {
      auto [_, raddr] = this->LoadFunctionReturnAddress(insn, block);
      auto npc = remill::LoadNextProgramCounterRef(block);
      auto pc = remill::LoadProgramCounterRef(block);
      builder.CreateStore(raddr, npc);
      builder.CreateStore(raddr, pc);
    } else {
      remill::AddTerminatingTailCall(block, intrinsics.error, intrinsics, true);
    }
    return !cc.stop;
  } else if (std::holds_alternative<anvill::Return>(override)) {
    remill::AddTerminatingTailCall(block, intrinsics.function_return,
                                   intrinsics, true);
    return false;
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
    DLOG(INFO) << "Ops emplace: " << inst_out->operands.size();
    return options.arch->DecodeInstruction(addr, inst_out->bytes, *inst_out,
                                           std::move(context));
  }
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


  bool ended_on_terminal = false;
  while (reached_addr < this->block_def.addr + this->block_def.size &&
         !ended_on_terminal) {
    auto addr = reached_addr;
    auto res = this->DecodeInstructionInto(addr, false, &inst, init_context);
    if (!res) {
      LOG(FATAL) << "Failed to decode insn in block " << std::hex << addr;
    }

    reached_addr += inst.bytes.size();

    // Even when something isn't supported or is invalid, we still lift
    // a call to a semantic, e.g.`INVALID_INSTRUCTION`, so we really want
    // to treat instruction lifting as an operation that can't fail.


    std::ignore = inst.GetLifter()->LiftIntoBlock(
        inst, bb, this->lifted_func->getArg(remill::kStatePointerArgNum),
        false /* is_delayed */);

    ended_on_terminal =
        !this->ApplyInterProceduralControlFlowOverride(inst, bb);
  }

  if (!ended_on_terminal) {
    llvm::IRBuilder<> builder(bb);

    builder.CreateStore(remill::LoadNextProgramCounter(bb, this->intrinsics),
                        this->lifted_func->getArg(remill::kNumBlockArgs));


    llvm::ReturnInst::Create(
        bb->getContext(), remill::LoadMemoryPointer(bb, this->intrinsics), bb);
  }
}


void BasicBlockLifter::InitializeLiveUncoveredRegs(llvm::Value *state_argument,
                                                   llvm::IRBuilder<> &ir) {
  auto need_to_init = this->block_context.LiveRegistersNotInVariablesAtEntry();

  for (auto init_reg : need_to_init) {
    auto reg_src_ptr = init_reg->AddressOf(state_argument, ir);
    auto reg_dest_ptr = init_reg->AddressOf(this->state_ptr, ir);
    auto reg_type =
        remill::RecontextualizeType(init_reg->type, this->llvm_context);
    ir.CreateStore(ir.CreateLoad(reg_type, reg_src_ptr), reg_dest_ptr);
  }
}

llvm::MDNode *BasicBlockLifter::GetBasicBlockAnnotation(uint64_t addr) const {
  return this->GetAddrAnnotation(addr, this->semantics_module->getContext());
}

BasicBlockFunction BasicBlockLifter::CreateBasicBlockFunction() {
  std::string name_ = "basic_block_func" + std::to_string(this->block_def.addr);
  auto &context = this->semantics_module->getContext();
  llvm::FunctionType *lifted_func_type =
      llvm::dyn_cast<llvm::FunctionType>(remill::RecontextualizeType(
          this->options.arch->LiftedFunctionType(), context));

  std::vector<llvm::Type *> params = std::vector(
      lifted_func_type->param_begin(), lifted_func_type->param_end());

  // pointer to varstruct
  params[remill::kStatePointerArgNum] = llvm::PointerType::get(context, 0);

  //next_pc_out
  params.push_back(llvm::PointerType::get(context, 0));


  // state structure
  params.push_back(llvm::PointerType::get(context, 0));


  llvm::FunctionType *func_type =
      llvm::FunctionType::get(lifted_func_type->getReturnType(), params, false);


  llvm::StringRef name(name_.data(), name_.size());
  auto func =
      llvm::Function::Create(func_type, llvm::GlobalValue::ExternalLinkage, 0u,
                             name, this->semantics_module);

  func->setMetadata(anvill::kBasicBlockMetadata,
                    GetBasicBlockAnnotation(this->block_def.addr));

  auto memory = remill::NthArgument(func, remill::kMemoryPointerArgNum);
  auto in_vars = remill::NthArgument(func, remill::kStatePointerArgNum);
  auto pc = remill::NthArgument(func, remill::kPCArgNum);
  auto next_pc_out = remill::NthArgument(func, remill::kNumBlockArgs);
  auto state = remill::NthArgument(func, remill::kNumBlockArgs + 1);

  memory->setName("memory");
  pc->setName("program_counter");
  next_pc_out->setName("next_pc_out");
  in_vars->setName("in_vars");
  state->setName("state");


  auto liftedty = this->options.arch->LiftedFunctionType();

  std::vector<llvm::Type *> new_params;
  new_params.reserve(liftedty->getNumParams() + 1);

  for (auto param : liftedty->params()) {
    new_params.push_back(param);
  }
  new_params.push_back(llvm::PointerType::get(context, 0));


  llvm::FunctionType *new_func_type = llvm::FunctionType::get(
      lifted_func_type->getReturnType(), new_params, false);


  this->lifted_func = llvm::Function::Create(
      new_func_type, llvm::GlobalValue::ExternalLinkage, 0u,
      std::string(name) + "lowlift", this->semantics_module);

  options.arch->InitializeEmptyLiftedFunction(this->lifted_func);


  llvm::BasicBlock::Create(context, "", func);
  auto &blk = func->getEntryBlock();
  llvm::IRBuilder<> ir(&blk);
  ir.CreateStore(memory, ir.CreateAlloca(memory->getType(), nullptr, "MEMORY"));

  this->state_ptr =
      this->AllocateAndInitializeStateStructure(&blk, options.arch);


  this->InitializeLiveUncoveredRegs(state, ir);
  // Put registers that are referencing the stack in terms of their displacement so that we
  // Can resolve these stack references later .


  auto sp_ptr = sp_reg->AddressOf(this->state_ptr, ir);
  // Initialize the stack pointer.
  ir.CreateStore(
      options.stack_pointer_init_procedure(ir, sp_reg, this->block_def.addr),
      sp_ptr);

  auto stack_offsets = this->block_context.GetStackOffsets();

  for (auto &reg_off : stack_offsets.affine_equalities) {
    if (reg_off.base_register && reg_off.base_register == this->sp_reg) {
      auto new_value = LifterOptions::SymbolicStackPointerInitWithOffset(
          ir, this->sp_reg, this->block_def.addr, reg_off.offset);
      StoreNativeValueToRegister(new_value, reg_off.target_register,
                                 type_provider.Dictionary(), intrinsics, &blk,
                                 this->state_ptr);
    }
  }

  this->UnpackLocals(ir, in_vars, this->state_ptr,
                     this->block_context.GetAvailableVariables());


  auto pc_arg = remill::NthArgument(func, remill::kPCArgNum);
  auto mem_arg = remill::NthArgument(func, remill::kMemoryPointerArgNum);


  func->addFnAttr(llvm::Attribute::NoInline);
  //func->setLinkage(llvm::GlobalValue::InternalLinkage);

  // TODO(Ian): memory pointer isnt quite right
  std::array<llvm::Value *, remill::kNumBlockArgs + 1> args = {
      this->state_ptr, pc, mem_arg, next_pc_out};
  auto ret_mem = ir.CreateCall(this->lifted_func, args);


  this->PackLocals(ir, this->state_ptr, in_vars,
                   this->block_context.GetAvailableVariables());

  ir.CreateRet(ret_mem);
  BasicBlockFunction bbf{func, pc_arg, in_vars, mem_arg, next_pc_out};

  return bbf;
}


llvm::StructType *BasicBlockLifter::StructTypeFromVars() const {
  return this->block_context.StructTypeFromVars(this->llvm_context);
}

// Packs in scope variables into a struct
void BasicBlockLifter::PackLocals(
    llvm::IRBuilder<> &bldr, llvm::Value *from_state_ptr,
    llvm::Value *into_vars, const std::vector<ParameterDecl> &decls) const {

  auto i32 = llvm::IntegerType::get(llvm_context, 32);
  uint64_t field_offset = 0;
  for (auto decl : decls) {
    auto ptr = bldr.CreateGEP(this->var_struct_ty, into_vars,
                              {llvm::ConstantInt::get(i32, 0),
                               llvm::ConstantInt::get(i32, field_offset)});
    field_offset += 1;

    auto state_loaded_value =
        LoadLiftedValue(decl, this->type_provider.Dictionary(),
                        this->intrinsics, bldr.GetInsertBlock(), from_state_ptr,
                        remill::LoadMemoryPointer(bldr, this->intrinsics));
    bldr.CreateStore(state_loaded_value, ptr);
  }
}

void BasicBlockLifter::UnpackLocals(
    llvm::IRBuilder<> &bldr, llvm::Value *returned_value,
    llvm::Value *into_state_ptr,
    const std::vector<ParameterDecl> &decls) const {
  uint64_t field_offset = 0;
  auto i32 = llvm::IntegerType::get(llvm_context, 32);
  for (auto decl : decls) {
    auto ptr = bldr.CreateGEP(this->var_struct_ty, returned_value,
                              {llvm::ConstantInt::get(i32, 0),
                               llvm::ConstantInt::get(i32, field_offset)});

    auto loaded_var_val = bldr.CreateLoad(decl.type, ptr, decl.name);
    field_offset += 1;
    auto new_mem_ptr = StoreNativeValue(
        loaded_var_val, decl, this->type_provider.Dictionary(),
        this->intrinsics, bldr.GetInsertBlock(), into_state_ptr,
        remill::LoadMemoryPointer(bldr, this->intrinsics));
    bldr.CreateStore(new_mem_ptr,
                     remill::LoadMemoryPointerRef(bldr.GetInsertBlock()));
  }
}


void BasicBlockLifter::CallBasicBlockFunction(
    llvm::IRBuilder<> &builder, llvm::Value *parent_state,
    const CallableBasicBlockFunction &cbfunc) const {


  std::vector<llvm::Value *> args(remill::kNumBlockArgs + 2);


  auto out_param_locals = builder.CreateAlloca(this->var_struct_ty);
  args[remill::kStatePointerArgNum] = out_param_locals;

  args[remill::kPCArgNum] = options.program_counter_init_procedure(
      builder, pc_reg, cbfunc.GetBlock().addr);
  args[remill::kMemoryPointerArgNum] =
      remill::LoadMemoryPointer(builder, this->intrinsics);

  args[remill::kNumBlockArgs] =
      remill::LoadNextProgramCounterRef(builder.GetInsertBlock());

  args[remill::kNumBlockArgs + 1] = parent_state;

  this->PackLocals(builder, parent_state, out_param_locals,
                   cbfunc.GetInScopeVaraibles());

  auto new_mem_ptr = builder.CreateCall(cbfunc.GetFunction(), args);

  auto mem_ptr_ref = remill::LoadMemoryPointerRef(builder.GetInsertBlock());

  builder.CreateStore(new_mem_ptr, mem_ptr_ref);

  this->UnpackLocals(builder, out_param_locals, parent_state,
                     cbfunc.GetInScopeVaraibles());
}


void CallableBasicBlockFunction::CallBasicBlockFunction(
    llvm::IRBuilder<> &add_to_llvm, llvm::Value *parent_state) const {
  this->bb_lifter.CallBasicBlockFunction(add_to_llvm, parent_state, *this);
}

CallableBasicBlockFunction BasicBlockLifter::LiftBasicBlock(
    const BasicBlockContext &block_context, const CodeBlock &block_def,
    const LifterOptions &options_, llvm::Module *semantics_module,
    const TypeTranslator &type_specifier) {

  return BasicBlockLifter(block_context, block_def, options_, semantics_module,
                          type_specifier)
      .LiftBasicBlockFunction();
}

BasicBlockLifter::BasicBlockLifter(const BasicBlockContext &block_context,
                                   const CodeBlock &block_def,
                                   const LifterOptions &options_,
                                   llvm::Module *semantics_module,
                                   const TypeTranslator &type_specifier)
    : CodeLifter(options_, semantics_module, type_specifier),
      block_context(block_context),
      block_def(block_def) {
  this->var_struct_ty = this->StructTypeFromVars();
}

CallableBasicBlockFunction::CallableBasicBlockFunction(
    llvm::Function *func, std::vector<ParameterDecl> in_scope_locals,
    CodeBlock block, BasicBlockLifter bb_lifter)
    : func(func),
      in_scope_locals(in_scope_locals),
      block(block),
      bb_lifter(std::move(bb_lifter)) {}


const CodeBlock &CallableBasicBlockFunction::GetBlock() const {
  return this->block;
}

llvm::Function *CallableBasicBlockFunction::GetFunction() const {
  return this->func;
}

const std::vector<ParameterDecl> &
CallableBasicBlockFunction::GetInScopeVaraibles() const {
  return this->in_scope_locals;
}

}  // namespace anvill