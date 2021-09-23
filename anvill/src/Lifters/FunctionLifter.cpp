/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "FunctionLifter.h"

#include <anvill/ABI.h>
#include <anvill/ITypeSpecification.h>
#include <anvill/Lifters/DeclLifter.h>
#include <anvill/Providers/MemoryProvider.h>
#include <anvill/Providers/TypeProvider.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/Compat/Error.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>

#include <sstream>
#include <unordered_set>

#include "EntityLifter.h"

namespace anvill {
namespace {

// Clear out LLVM variable names. They're usually not helpful.
static void ClearVariableNames(llvm::Function *func) {
  for (auto &block : *func) {
    block.setName(llvm::Twine::createNull());
    for (auto &inst : block) {
      if (inst.hasName()) {
        inst.setName(llvm::Twine::createNull());
      }
    }
  }
}

// Compatibility function for performing a single step of inlining.
static llvm::InlineResult InlineFunction(llvm::CallBase *call,
                                         llvm::InlineFunctionInfo &info) {
#if LLVM_VERSION_NUMBER < LLVM_VERSION(11, 0)
  return llvm::InlineFunction(call, info);
#else
  return llvm::InlineFunction(*call, info);
#endif
}

// A function that ensures that the memory pointer escapes, and thus none of
// the memory writes at the end of a function are lost.
static llvm::Function *
GetMemoryEscapeFunc(const remill::IntrinsicTable &intrinsics) {
  const auto module = intrinsics.error->getParent();
  auto &context = module->getContext();

  if (auto func = module->getFunction(kMemoryPointerEscapeFunction)) {
    return func;
  }

  llvm::Type *params[] = {
      remill::NthArgument(intrinsics.error, remill::kMemoryPointerArgNum)
          ->getType()};
  auto type =
      llvm::FunctionType::get(llvm::Type::getVoidTy(context), params, false);
  return llvm::Function::Create(type, llvm::GlobalValue::ExternalLinkage,
                                kMemoryPointerEscapeFunction.data(), module);
}

// We're calling a remill intrinsic and we want to "mute" the escape of the
// `State` pointer by replacing it with an `undef` value. This permits
// optimizations while allowing us to still observe what reaches the `pc`
// argument of the intrinsic. This is valuable for function return intrinsics,
// because it lets us verify that the value that we initialize into the return
// address location actually reaches the `pc` parameter of the
// `__remill_function_return`.
static void MuteStateEscape(llvm::CallInst *call) {
  auto state_ptr_arg = call->getArgOperand(remill::kStatePointerArgNum);
  auto undef_val = llvm::UndefValue::get(state_ptr_arg->getType());
  call->setArgOperand(remill::kStatePointerArgNum, undef_val);
}

// This returns a special anvill built-in used to describe jumps tables
// inside lifted code; It takes the address type to generate the function
// parameters of correct type.
static llvm::Function *GetAnvillSwitchFunc(llvm::Module &module, llvm::Type *type,
                                           bool complete) {

  const auto &func_name =
      complete ? kAnvillSwitchCompleteFunc : kAnvillSwitchIncompleteFunc;

  auto func = module.getFunction(func_name);
  if (func != nullptr) {
    return func;
  }

  auto &context = module.getContext();
  llvm::Type* func_parameters[] = {type};

  auto func_type = llvm::FunctionType::get(type, func_parameters, true);

  func = llvm::Function::Create(func_type, llvm::GlobalValue::ExternalLinkage,
                                func_name, module);

  func->addFnAttr(llvm::Attribute::ReadNone);

  return func;
}

// Annotate and instruction with the `id` annotation if that instruction
// is unannotated.
static void AnnotateInstruction(llvm::Instruction *inst, unsigned id,
                                llvm::MDNode *annot) {
  if (annot && !inst->getMetadata(id)) {
    inst->setMetadata(id, annot);
  }
}

// Annotate and instruction with the `id` annotation if that instruction
// is unannotated.
static void AnnotateInstructions(llvm::BasicBlock *block, unsigned id,
                                 llvm::MDNode *annot) {
  if (annot) {
    for (auto &inst : *block) {
      AnnotateInstruction(&inst, id, annot);
    }
  }
}

}  // namespace

FunctionLifter::~FunctionLifter(void) {}

FunctionLifter::FunctionLifter(const LifterOptions &options_,
                               MemoryProvider &memory_provider_,
                               TypeProvider &type_provider_)
    : options(options_),
      memory_provider(memory_provider_),
      type_provider(type_provider_),
      semantics_module(remill::LoadArchSemantics(options.arch)),
      llvm_context(semantics_module->getContext()),
      intrinsics(semantics_module.get()),
      inst_lifter(options.arch, intrinsics),
      pc_reg(options.arch->RegisterByName(
          options.arch->ProgramCounterRegisterName())),
      sp_reg(options.arch->RegisterByName(
          options.arch->StackPointerRegisterName())),
      is_sparc(options.arch->IsSPARC32() || options.arch->IsSPARC64()),
      is_x86_or_amd64(options.arch->IsX86() || options.arch->IsAMD64()),
      i8_type(llvm::Type::getInt8Ty(llvm_context)),
      i8_zero(llvm::Constant::getNullValue(i8_type)),
      i32_type(llvm::Type::getInt32Ty(llvm_context)),
      mem_ptr_type(
          llvm::dyn_cast<llvm::PointerType>(remill::RecontextualizeType(
              options.arch->MemoryPointerType(), llvm_context))),
      state_ptr_type(
          llvm::dyn_cast<llvm::PointerType>(remill::RecontextualizeType(
              options.arch->StatePointerType(), llvm_context))),
      address_type(
          llvm::Type::getIntNTy(llvm_context, options.arch->address_size)),
      pc_reg_type(pc_reg->type) {

  if (options.pc_metadata_name) {
    pc_annotation_id = llvm_context.getMDKindID(options.pc_metadata_name);
  }
}

// Helper to get the basic block to contain the instruction at `addr`. This
// function drives a work list, where the first time we ask for the
// instruction at `addr`, we enqueue a bit of work to decode and lift that
// instruction.
llvm::BasicBlock *FunctionLifter::GetOrCreateBlock(uint64_t addr) {
  const auto from_pc = curr_inst ? curr_inst->pc : 0;
  auto &block = edge_to_dest_block[{from_pc, addr}];
  if (block) {
    return block;
  }

  std::stringstream ss;
  ss << "inst_" << std::hex << addr;
  block = llvm::BasicBlock::Create(llvm_context, ss.str(), lifted_func);

  // NOTE(pag): We always add to the work list without consulting/updating
  //            `addr_to_block` so that we can observe self-tail-calls and
  //            lift them as such, rather than as jumps back into the first
  //            lifted block.
  edge_work_list.emplace(addr, from_pc);

  return block;
}

llvm::BasicBlock *FunctionLifter::GetOrCreateTargetBlock(uint64_t addr) {
  return GetOrCreateBlock(options.ctrl_flow_provider->GetRedirection(addr));
}

// Try to decode an instruction at address `addr` into `*inst_out`. Returns
// `true` is successful and `false` otherwise. `is_delayed` tells the decoder
// whether or not the instruction being decoded is being decoded inside of a
// delay slot of another instruction.
bool FunctionLifter::DecodeInstructionInto(const uint64_t addr, bool is_delayed,
                                           remill::Instruction *inst_out) {
  static const auto max_inst_size = options.arch->MaxInstructionSize();
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
    return options.arch->DecodeDelayedInstruction(addr, inst_out->bytes,
                                                  *inst_out);
  } else {
    return options.arch->DecodeInstruction(addr, inst_out->bytes, *inst_out);
  }
}

// Visit an invalid instruction. An invalid instruction is a sequence of
// bytes which cannot be decoded, or an empty byte sequence.
void FunctionLifter::VisitInvalid(const remill::Instruction &inst,
                                  llvm::BasicBlock *block) {
  MuteStateEscape(remill::AddTerminatingTailCall(block, intrinsics.error));
}

// Visit an error instruction. An error instruction is guaranteed to trap
// execution somehow, e.g. `ud2` on x86. Error instructions are treated
// similarly to invalid instructions, with the exception that they can have
// delay slots, and therefore the subsequent instruction may actually execute
// prior to the error.
void FunctionLifter::VisitError(const remill::Instruction &inst,
                                remill::Instruction *delayed_inst,
                                llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  MuteStateEscape(remill::AddTerminatingTailCall(block, intrinsics.error));
}

// Visit a normal instruction. Normal instructions have straight line control-
// flow semantics, i.e. after executing the instruction, execution proceeds
// to the next instruction (`inst.next_pc`).
void FunctionLifter::VisitNormal(const remill::Instruction &inst,
                                 llvm::BasicBlock *block) {
  llvm::BranchInst::Create(GetOrCreateTargetBlock(inst.next_pc), block);
}

// Visit a no-op instruction. These behave identically to normal instructions
// from a control-flow perspective.
void FunctionLifter::VisitNoOp(const remill::Instruction &inst,
                               llvm::BasicBlock *block) {
  VisitNormal(inst, block);
}

// Visit a direct jump control-flow instruction. The target of the jump is
// known at decode time, and the target address is available in
// `inst.branch_taken_pc`. Execution thus needs to transfer to the instruction
// (and thus `llvm::BasicBlock`) associated with `inst.branch_taken_pc`.
void FunctionLifter::VisitDirectJump(const remill::Instruction &inst,
                                     remill::Instruction *delayed_inst,
                                     llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  llvm::BranchInst::Create(GetOrCreateTargetBlock(inst.branch_taken_pc), block);
}

// Visit an indirect jump control-flow instruction. This may be register- or
// memory-indirect, e.g. `jmp rax` or `jmp [rax]` on x86. Thus, the target is
// not know a priori and our default mechanism for handling this is to perform
// a tail-call to the `__remill_jump` function, whose role is to be a stand-in
// something that enacts the effect of "transfer to target."
void FunctionLifter::VisitIndirectJump(const remill::Instruction &inst,
                                       remill::Instruction *delayed_inst,
                                       llvm::BasicBlock *block) {

  VisitDelayedInstruction(inst, delayed_inst, block, true);

  // Attempt to get the target list for this control flow instruction
  // so that we can handle this jump in a less generic way
  auto maybe_target_list =
      options.ctrl_flow_provider->TryGetControlFlowTargets(inst.pc);

  auto add_remill_jump{true};
  llvm::BasicBlock *current_bb = block;

  // This is a list of the possibilities we want to cover:
  //
  // 1. No target: AddTerminatingTailCall
  // 2. Single target, complete: normal jump
  // 3. Multiple targets, complete: switch with no default case
  // 4. Single or multiple targets, not complete: switch with default case
  //    containing AddTerminatingTailCall

  if (maybe_target_list.has_value()) {
    const auto &target_list = maybe_target_list.value();

    // If the target list is complete and has only one destination, then we
    // can handle it as normal jump
    if (target_list.destination_list.size() == 1U && target_list.complete) {
      add_remill_jump = false;

      auto destination = target_list.destination_list.front();
      llvm::BranchInst::Create(GetOrCreateTargetBlock(destination), block);

    // We have multiple destinations. Handle this with a switch. If the target
    // list is not marked as complete, then we'll still add __remill_jump
    // inside the default block
    } else {
      llvm::BasicBlock *default_case{nullptr};

      // Create a default case that is not reachable
      if (target_list.complete) {
        add_remill_jump = false;
        default_case = llvm::BasicBlock::Create(llvm_context, "", lifted_func);

        llvm::IRBuilder<> builder(default_case);
        builder.CreateUnreachable();

      // Create a default case that will contain the __remill_jump. For this
      // to work, we need to update `current_bb`
      } else {
        add_remill_jump = true;

        default_case = llvm::BasicBlock::Create(llvm_context, "", lifted_func);
        current_bb = default_case;
      }

      // Create the parameters for the special anvill switch
      auto pc = inst_lifter.LoadRegValue(
          block, state_ptr, options.arch->ProgramCounterRegisterName());

      std::vector<llvm::Value *> switch_parameters;
      switch_parameters.push_back(pc);

      for (auto destination : target_list.destination_list) {
        auto dest_as_value = GenerateProgramCounter(block, destination);
        switch_parameters.push_back(dest_as_value);
      }

      // Invoke the anvill switch
      auto &module = *block->getModule();
      auto anvill_switch_func =
          GetAnvillSwitchFunc(module, address_type, target_list.complete);

      llvm::IRBuilder<> ir(block);
      auto next_pc = ir.CreateCall(anvill_switch_func, switch_parameters);

      // Now use the anvill switch output with a SwitchInst, mapping cases
      // by index
      auto dest_count = target_list.destination_list.size();
      auto switch_inst = ir.CreateSwitch(next_pc, default_case, dest_count);

      for (std::size_t dest_id{0U}; dest_id < dest_count; ++dest_id) {
        auto dest = target_list.destination_list.at(dest_id);
        auto dest_block = GetOrCreateTargetBlock(dest);

        auto dest_id_as_value = llvm::ConstantInt::get(address_type, dest_id);
        switch_inst->addCase(dest_id_as_value, dest_block);
      }
    }
  }

  if (add_remill_jump) {

    // Either we didn't find any target list from the control flow provider, or we
    // did but it wasn't marked as `complete`
    remill::AddTerminatingTailCall(current_bb, intrinsics.jump);
  }
}

// Visit a conditional indirect jump control-flow instruction. This is a mix
// between indirect jumps and conditional jumps that appears on the
// ARMv7 (AArch32) architecture, where many instructions are predicated.
void FunctionLifter::VisitConditionalIndirectJump(
    const remill::Instruction &inst, remill::Instruction *delayed_inst,
    llvm::BasicBlock *block) {
  const auto lifted_func = block->getParent();
  const auto cond = remill::LoadBranchTaken(block);
  const auto taken_block =
      llvm::BasicBlock::Create(llvm_context, "", lifted_func);
  const auto not_taken_block =
      llvm::BasicBlock::Create(llvm_context, "", lifted_func);
  llvm::BranchInst::Create(taken_block, not_taken_block, cond, block);
  VisitDelayedInstruction(inst, delayed_inst, taken_block, true);
  VisitDelayedInstruction(inst, delayed_inst, not_taken_block, false);
  remill::AddTerminatingTailCall(taken_block, intrinsics.jump);
  llvm::BranchInst::Create(GetOrCreateTargetBlock(inst.branch_not_taken_pc),
                           not_taken_block);
}

// Visit a function return control-flow instruction, which is a form of
// indirect control-flow, but with a certain semantic associated with
// returning from a function. This is treated similarly to indirect jumps,
// except the `__remill_function_return` function is tail-called.
void FunctionLifter::VisitFunctionReturn(const remill::Instruction &inst,
                                         remill::Instruction *delayed_inst,
                                         llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  MuteStateEscape(
      remill::AddTerminatingTailCall(block, intrinsics.function_return));
}

// Visit a conditional function return control-flow instruction, which is a
// variant that is half-way between a return and a conditional jump. These
// are possible on ARMv7 (AArch32).
void FunctionLifter::VisitConditionalFunctionReturn(
    const remill::Instruction &inst, remill::Instruction *delayed_inst,
    llvm::BasicBlock *block) {
  const auto lifted_func = block->getParent();
  const auto cond = remill::LoadBranchTaken(block);
  const auto taken_block =
      llvm::BasicBlock::Create(llvm_context, "", lifted_func);
  const auto not_taken_block =
      llvm::BasicBlock::Create(llvm_context, "", lifted_func);
  llvm::BranchInst::Create(taken_block, not_taken_block, cond, block);
  VisitDelayedInstruction(inst, delayed_inst, taken_block, true);
  MuteStateEscape(
      remill::AddTerminatingTailCall(taken_block, intrinsics.function_return));
  VisitDelayedInstruction(inst, delayed_inst, not_taken_block, false);
  llvm::BranchInst::Create(GetOrCreateTargetBlock(inst.branch_not_taken_pc),
                           not_taken_block);
}

std::optional<FunctionDecl>
FunctionLifter::TryGetTargetFunctionType(std::uint64_t address) {
  auto redirected_addr = options.ctrl_flow_provider->GetRedirection(address);

  // In case we get redirected but still fail, try once more with the original
  // address
  auto opt_function_decl = type_provider.TryGetFunctionType(redirected_addr);
  if (!opt_function_decl.has_value() && redirected_addr != address) {

    // When we retry using the original address, still keep the (possibly)
    // redirected value
    opt_function_decl = type_provider.TryGetFunctionType(address);
  }

  if (!opt_function_decl.has_value()) {
    return std::nullopt;
  }

  // The `redirected_addr` value can either be the original one or the
  // redirected address
  auto function_decl = opt_function_decl.value();
  function_decl.address = redirected_addr;

  return function_decl;
}

// Try to resolve `inst.branch_taken_pc` to a lifted function, and introduce
// a function call to that address in `block`. Failing this, add a call
// to `__remill_function_call`.
void FunctionLifter::CallFunction(const remill::Instruction &inst,
                                  llvm::BasicBlock *block) {

  // First, try to see if it's actually related to another function. This is
  // equivalent to a tail-call in the original code.
  const auto maybe_other_decl = TryGetTargetFunctionType(inst.branch_taken_pc);

  if (maybe_other_decl.has_value()) {
    auto other_decl = maybe_other_decl.value();

    if (const auto other_func = DeclareFunction(other_decl)) {
      const auto mem_ptr_from_call =
          TryCallNativeFunction(other_decl.address, other_func, block);

      if (!mem_ptr_from_call) {
        LOG(ERROR) << "Failed to call native function at address " << std::hex
                   << other_decl.address << " via call at address " << inst.pc
                   << " in function at address " << func_address << std::dec;

        // If we fail to create an ABI specification for this function then
        // treat this as a call to an unknown address.
        remill::AddCall(block, intrinsics.function_call);
      }
    } else {
      LOG(ERROR) << "Failed to call non-executable memory or invalid address "
                 << std::hex << inst.branch_taken_pc << " via call at address "
                 << inst.pc << " in function at address " << func_address
                 << std::dec;

      // TODO(pag): Make call `intrinsics.error`?
      remill::AddCall(block, intrinsics.function_call);
    }
  } else {
    LOG(ERROR) << "Missing type information for function at address "
               << std::hex << inst.branch_taken_pc << ", called at address "
               << inst.pc << " in function at address " << func_address
               << std::dec;

    // If we do not have a function declaration, treat this as a call
    // to an unknown address.
    remill::AddCall(block, intrinsics.function_call);
  }
}

// Visit a direct function call control-flow instruction. The target is known
// at decode time, and its realized address is stored in
// `inst.branch_taken_pc`. In practice, what we do in this situation is try
// to call the lifted function function at the target address.
void FunctionLifter::VisitDirectFunctionCall(const remill::Instruction &inst,
                                             remill::Instruction *delayed_inst,
                                             llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  CallFunction(inst, block);
  VisitAfterFunctionCall(inst, block);
}

// Visit a conditional direct function call control-flow instruction. The
// target is known at decode time, and its realized address is stored in
// `inst.branch_taken_pc`. In practice, what we do in this situation is try
// to call the lifted function function at the target address if the condition
// is satisfied. Note that it is up to the semantics of the conditional call
// instruction to "tell us" if the condition is met.
void FunctionLifter::VisitConditionalDirectFunctionCall(
    const remill::Instruction &inst, remill::Instruction *delayed_inst,
    llvm::BasicBlock *block) {
  const auto lifted_func = block->getParent();
  const auto cond = remill::LoadBranchTaken(block);
  const auto taken_block =
      llvm::BasicBlock::Create(llvm_context, "", lifted_func);
  const auto not_taken_block =
      llvm::BasicBlock::Create(llvm_context, "", lifted_func);
  llvm::BranchInst::Create(taken_block, not_taken_block, cond, block);
  VisitDelayedInstruction(inst, delayed_inst, taken_block, true);
  CallFunction(inst, taken_block);
  VisitAfterFunctionCall(inst, taken_block);
  VisitDelayedInstruction(inst, delayed_inst, not_taken_block, false);
  llvm::BranchInst::Create(GetOrCreateTargetBlock(inst.branch_not_taken_pc),
                           not_taken_block);
}

// Visit an indirect function call control-flow instruction. Similar to
// indirect jumps, we invoke an intrinsic function, `__remill_function_call`;
// however, unlike indirect jumps, we do not tail-call this intrinsic, and
// we continue lifting at the instruction where execution will resume after
// the callee returns. Thus, lifted bitcode maintains the call graph structure
// as it presents itself in the binary.
void FunctionLifter::VisitIndirectFunctionCall(
    const remill::Instruction &inst, remill::Instruction *delayed_inst,
    llvm::BasicBlock *block) {

  VisitDelayedInstruction(inst, delayed_inst, block, true);
  remill::AddCall(block, intrinsics.function_call);
  VisitAfterFunctionCall(inst, block);
}

// Visit a conditional indirect function call control-flow instruction.
// This is a cross between conditional jumps and indirect function calls.
void FunctionLifter::VisitConditionalIndirectFunctionCall(
    const remill::Instruction &inst, remill::Instruction *delayed_inst,
    llvm::BasicBlock *block) {
  const auto lifted_func = block->getParent();
  const auto cond = remill::LoadBranchTaken(block);
  const auto taken_block =
      llvm::BasicBlock::Create(llvm_context, "", lifted_func);
  const auto not_taken_block =
      llvm::BasicBlock::Create(llvm_context, "", lifted_func);
  llvm::BranchInst::Create(taken_block, not_taken_block, cond, block);
  VisitDelayedInstruction(inst, delayed_inst, taken_block, true);
  remill::AddCall(taken_block, intrinsics.function_call);
  VisitAfterFunctionCall(inst, taken_block);
  VisitDelayedInstruction(inst, delayed_inst, not_taken_block, false);
  llvm::BranchInst::Create(GetOrCreateTargetBlock(inst.branch_not_taken_pc),
                           not_taken_block);
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
FunctionLifter::LoadFunctionReturnAddress(const remill::Instruction &inst,
                                          llvm::BasicBlock *block) {

  const auto pc = inst.branch_not_taken_pc;

  // The semantics for handling a call save the expected return program counter
  // into a local variable.
  auto ret_pc =
      inst_lifter.LoadRegValue(block, state_ptr, remill::kReturnPCVariableName);
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
  // the size of the value to return. See "Programming Note" in v8 manual, B.31,
  // p 137.
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

// Enact relevant control-flow changed after a function call. This figures
// out the return address targeted by the callee and links it into the
// control-flow graph.
void FunctionLifter::VisitAfterFunctionCall(const remill::Instruction &inst,
                                            llvm::BasicBlock *block) {
  const auto [ret_pc, ret_pc_val] = LoadFunctionReturnAddress(inst, block);
  const auto pc_ptr =
      inst_lifter.LoadRegAddress(block, state_ptr, remill::kPCVariableName);
  const auto next_pc_ptr =
      inst_lifter.LoadRegAddress(block, state_ptr, remill::kNextPCVariableName);

  llvm::IRBuilder<> ir(block);
  ir.CreateStore(ret_pc_val, pc_ptr, false);
  ir.CreateStore(ret_pc_val, next_pc_ptr, false);
  ir.CreateBr(GetOrCreateTargetBlock(ret_pc));
}

// Visit a conditional control-flow branch. Both the taken and not taken
// targets are known by the decoder and their addresses are available in
// `inst.branch_taken_pc` and `inst.branch_not_taken_pc`, respectively.
// Here we need to orchestrate the two-way control-flow, as well as the
// possible execution of a delayed instruction on either or both paths,
// depending on the presence/absence of delay slot annulment bits.
void FunctionLifter::VisitConditionalBranch(const remill::Instruction &inst,
                                            remill::Instruction *delayed_inst,
                                            llvm::BasicBlock *block) {
  std::stringstream taken_ss;
  taken_ss
      << "inst_" << std::hex << inst.pc << "_taken_"
      << inst.branch_taken_pc;

  std::stringstream not_taken_ss;
  not_taken_ss
      << "inst_" << std::hex << inst.pc << "_not_taken_"
      << inst.branch_not_taken_pc;

  const auto lifted_func = block->getParent();
  const auto cond = remill::LoadBranchTaken(block);
  const auto taken_block =
      llvm::BasicBlock::Create(llvm_context, taken_ss.str(), lifted_func);
  const auto not_taken_block =
      llvm::BasicBlock::Create(llvm_context, not_taken_ss.str(), lifted_func);
  llvm::BranchInst::Create(taken_block, not_taken_block, cond, block);
  VisitDelayedInstruction(inst, delayed_inst, taken_block, true);
  VisitDelayedInstruction(inst, delayed_inst, not_taken_block, false);
  llvm::BranchInst::Create(GetOrCreateTargetBlock(inst.branch_taken_pc),
                           taken_block);
  llvm::BranchInst::Create(GetOrCreateTargetBlock(inst.branch_not_taken_pc),
                           not_taken_block);
}

// Visit an asynchronous hyper call control-flow instruction. These are non-
// local control-flow transfers, such as system calls. We treat them like
// indirect function calls.
void FunctionLifter::VisitAsyncHyperCall(const remill::Instruction &inst,
                                         remill::Instruction *delayed_inst,
                                         llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  remill::AddTerminatingTailCall(block, intrinsics.async_hyper_call);
}

// Visit conditional asynchronous hyper calls. These are conditional, non-
// local control-flow transfers, e.g. `bound` on x86.
void FunctionLifter::VisitConditionalAsyncHyperCall(
    const remill::Instruction &inst, remill::Instruction *delayed_inst,
    llvm::BasicBlock *block) {
  const auto lifted_func = block->getParent();
  const auto cond = remill::LoadBranchTaken(block);
  const auto taken_block =
      llvm::BasicBlock::Create(llvm_context, "", lifted_func);
  const auto not_taken_block =
      llvm::BasicBlock::Create(llvm_context, "", lifted_func);
  llvm::BranchInst::Create(taken_block, not_taken_block, cond, block);
  VisitDelayedInstruction(inst, delayed_inst, taken_block, true);
  VisitDelayedInstruction(inst, delayed_inst, not_taken_block, false);

  remill::AddTerminatingTailCall(taken_block, intrinsics.async_hyper_call);

  llvm::BranchInst::Create(GetOrCreateTargetBlock(inst.branch_not_taken_pc),
                           not_taken_block);
}

// Visit (and thus lift) a delayed instruction. When lifting a delayed
// instruction, we need to know if we're one the taken path of a control-flow
// edge, or on the not-taken path. Delayed instructions appear physically
// after some instructions, but execute logically before them in the
// CPU pipeline. They are basically a way for hardware designers to push
// the effort of keeping the pipeline full to compiler developers.
void FunctionLifter::VisitDelayedInstruction(const remill::Instruction &inst,
                                             remill::Instruction *delayed_inst,
                                             llvm::BasicBlock *block,
                                             bool on_taken_path) {
  if (delayed_inst && options.arch->NextInstructionIsDelayed(
                          inst, *delayed_inst, on_taken_path)) {
    inst_lifter.LiftIntoBlock(*delayed_inst, block, state_ptr, true);

    const auto inst_annotation = GetPCAnnotation(delayed_inst->pc);
    AnnotateInstructions(block, pc_annotation_id, inst_annotation);
  }
}

// Creates a type hint taint value that we can hook into downstream in the
// optimization process.
//
// This function encodes type information within symbolic functions so the type
// information can survive optimization. It should turn some instruction like
//
//    %1 = add %4, 1
//
// into:
//
//    %1 = add %4, 1
//    %2 = __anvill_type_<uid>(<%4's type> %4)
//    %3 = ptrtoint %2 goal_type
llvm::Function *FunctionLifter::GetOrCreateTaintedFunction(
    llvm::Type *current_type, llvm::Type *goal_type,
    llvm::BasicBlock *curr_block, const remill::Register *reg, uint64_t pc) {

  const auto &dl = semantics_module->getDataLayout();

  // Consider adding in:
  // std::hex << pc << "_" << reg->name

  std::stringstream ss;
  ss << kTypeHintFunctionPrefix
     << ITypeSpecification::TypeToString(*goal_type, dl, true);
  const auto func_name = ss.str();

  llvm::Type *return_type = goal_type;

  auto anvill_type_fn_ty =
      llvm::FunctionType::get(return_type, {current_type}, false);

  // Return the function if it exists.
  auto func = semantics_module->getFunction(func_name);
  if (func) {
    return func;
  }

  // Create the function if not, and make LLVM treat it like an uninterpreted
  // function that doesn't read memory. This improves LLVM's ability to optimize
  // uses of the function.
  func = llvm::Function::Create(anvill_type_fn_ty,
                                llvm::GlobalValue::ExternalLinkage, func_name,
                                semantics_module.get());
  func->addFnAttr(llvm::Attribute::ReadNone);
  return func;
}

// Instrument an instruction. This inject a `printf`-like function call just
// before a lifted instruction to aid in tracking the provenance of register
// values, and relating them back to original instructions.
//
// TODO(pag): In future, this mechanism should be used to provide a feedback
//            loop, or to provide information to the `TypeProvider` for future
//            re-lifting of code.
//
// TODO(pag): Right now, this feature is enabled by a command-line flag, and
//            that flag is tested in `VisitInstruction`; we should move
//            lifting configuration decisions out of here so that we can pass
//            in a kind of `LiftingOptions` type that changes the lifter's
//            behavior.
void FunctionLifter::InstrumentDataflowProvenance(llvm::BasicBlock *block) {
  if (!data_provenance_function) {
    data_provenance_function =
        semantics_module->getFunction(kAnvillDataProvenanceFunc);

    if (!data_provenance_function) {
      llvm::Type *args[] = {mem_ptr_type, pc_reg_type};
      auto fty = llvm::FunctionType::get(mem_ptr_type, args, true);
      data_provenance_function = llvm::Function::Create(
          fty, llvm::GlobalValue::ExternalLinkage,
          kAnvillDataProvenanceFunc, *semantics_module);
    }
  }

  std::vector<llvm::Value *> args;
  llvm::IRBuilder<> ir(block);
  args.push_back(ir.CreateLoad(mem_ptr_type, mem_ptr_ref));
  args.push_back(llvm::ConstantInt::get(pc_reg_type, curr_inst->pc));
  options.arch->ForEachRegister([&](const remill::Register *reg) {
    if (reg != pc_reg && reg != sp_reg && reg->EnclosingRegister() == reg) {
      args.push_back(inst_lifter.LoadRegValue(block, state_ptr, reg->name));
    }
  });

  ir.CreateStore(ir.CreateCall(data_provenance_function, args), mem_ptr_ref);
}

// Adds a 'breakpoint' instrumentation, which calls functions that are named
// with an instruction's address just before that instruction executes. These
// are nifty to spot checking bitcode. This function is used like:
//
//      mem = breakpoint_<hexaddr>(mem, PC, NEXT_PC)
//
// That way, we can look at uses and compare the second argument to the
// hex address encoded in the function name, and also look at the third argument
// and see if it corresponds to the subsequent instruction address.
void FunctionLifter::InstrumentCallBreakpointFunction(llvm::BasicBlock *block) {
  std::stringstream ss;
  ss << "breakpoint_" << std::hex << curr_inst->pc;

  const auto func_name = ss.str();
  auto module = block->getModule();
  auto func = module->getFunction(func_name);
  if (!func) {
    llvm::Type *const params[] = {mem_ptr_type, address_type, address_type};
    const auto fty = llvm::FunctionType::get(mem_ptr_type, params, false);
    func = llvm::Function::Create(fty, llvm::GlobalValue::ExternalLinkage,
                                  func_name, module);

    // Make sure to keep this function around (along with `ExternalLinkage`).
    func->addFnAttr(llvm::Attribute::OptimizeNone);
    func->removeFnAttr(llvm::Attribute::AlwaysInline);
    func->removeFnAttr(llvm::Attribute::InlineHint);
    func->addFnAttr(llvm::Attribute::NoInline);
    func->addFnAttr(llvm::Attribute::ReadNone);

    llvm::IRBuilder<> ir(llvm::BasicBlock::Create(llvm_context, "", func));
    ir.CreateRet(remill::NthArgument(func, 0));
  }

  llvm::Value *args[] = {
      new llvm::LoadInst(mem_ptr_type, mem_ptr_ref,
                         llvm::Twine::createNull(), block),
      inst_lifter.LoadRegValue(block, state_ptr, remill::kPCVariableName),
      inst_lifter.LoadRegValue(block, state_ptr, remill::kNextPCVariableName)};
  llvm::IRBuilder<> ir(block);
  ir.CreateCall(func, args);
}

// Visit a type hinted register at the current instruction. We use this
// information to try to improve lifting of possible pointers later on
// in the optimization process.
void FunctionLifter::VisitTypedHintedRegister(
    llvm::BasicBlock *block, const std::string &reg_name, llvm::Type *type,
    std::optional<uint64_t> maybe_value) {

  // Only operate on pointer-sized integer registers that are not sub-registers.
  const auto reg = options.arch->RegisterByName(reg_name);
  if (reg->EnclosingRegister() != reg ||
      !reg->type->isIntegerTy(options.arch->address_size)) {
    return;
  }

  llvm::IRBuilder irb(block);
  auto reg_pointer = inst_lifter.LoadRegAddress(block, state_ptr, reg_name);
  llvm::Value *reg_value = nullptr;

  // If we have a concrete value that is being provided for this value, then
  // save it into the `State` structure. This improves our ability to optimize.
  if (options.store_inferred_register_values && maybe_value) {
    reg_value = irb.CreateLoad(reg->type, reg_pointer);
    reg_value = llvm::ConstantInt::get(reg->type, *maybe_value);
    irb.CreateStore(reg_value, reg_pointer);
  }

  if (!type->isPointerTy()) {
    return;
  }

  if (!reg_value) {
    reg_value = irb.CreateLoad(reg->type, reg_pointer);
  }

  // Creates a function that returns a higher-level type, as provided by a
  // `TypeProider`and takes an argument of (reg_type)
  const auto taint_func =
      GetOrCreateTaintedFunction(reg->type, type, block, reg, curr_inst->pc);
  llvm::Value *tainted_call = irb.CreateCall(taint_func, reg_value);

  // Cast the result of this call to the goal type.
  llvm::Value *replacement_reg = irb.CreatePtrToInt(tainted_call, reg->type);

  // Store the value back, this keeps the replacement_reg cast around.
  irb.CreateStore(replacement_reg, reg_pointer);
}

// Visit an instruction, and lift it into a basic block. Then, based off of
// the category of the instruction, invoke one of the category-specific
// lifters to enact a change in control-flow.
void FunctionLifter::VisitInstruction(remill::Instruction &inst,
                                      llvm::BasicBlock *block) {
  curr_inst = &inst;

  // TODO(pag): Consider emitting calls to the `llvm.pcmarker` intrinsic. Figure
  //            out if the `i32` parameter is different on 64-bit targets, or
  //            if it's actually a metadata ID.

  // Reserve space for an instrucion that will go into a delay slot, in case it
  // is needed. This is an uncommon case, so avoid instantiating a new
  // Instruction unless it is actually needed. The instruction instantition into
  // this buffer happens via a placement new call later on.
  std::aligned_storage<sizeof(remill::Instruction),
                       alignof(remill::Instruction)>::type delayed_inst_storage;

  remill::Instruction *delayed_inst = nullptr;

  // Try to find any register type hints that we can use later to improve
  // pointer lifting.
  if (options.symbolic_register_types) {
    type_provider.QueryRegisterStateAtInstruction(
        func_address, inst.pc,
        [=](const std::string &reg_name, llvm::Type *type,
            std::optional<uint64_t> maybe_value) {
          VisitTypedHintedRegister(block, reg_name, type, maybe_value);
        });
  }

  if (options.track_provenance) {
    InstrumentDataflowProvenance(block);
  }

  if (options.add_breakpoints) {
    InstrumentCallBreakpointFunction(block);
  }

  // Even when something isn't supported or is invalid, we still lift
  // a call to a semantic, e.g.`INVALID_INSTRUCTION`, so we really want
  // to treat instruction lifting as an operation that can't fail.
  (void) inst_lifter.LiftIntoBlock(inst, block, state_ptr,
                                   false /* is_delayed */);

  // Figure out if we have to decode the subsequent instruction as a delayed
  // instruction.
  if (options.arch->MayHaveDelaySlot(inst)) {
    delayed_inst = new (&delayed_inst_storage) remill::Instruction;
    if (!DecodeInstructionInto(inst.delayed_pc, true /* is_delayed */,
                               delayed_inst)) {
      LOG(ERROR) << "Unable to decode or use delayed instruction at "
                 << std::hex << inst.delayed_pc << std::dec << " of "
                 << inst.Serialize();
    }
  }

  // Do an initial annotation of instructions injected by `LiftIntoBlock`,
  // and prior to any lifting of a delayed instruction that might happen
  // in any of the below `Visit*` calls.
  const auto inst_annotation = GetPCAnnotation(inst.pc);
  AnnotateInstructions(block, pc_annotation_id, inst_annotation);

  switch (inst.category) {

    // Invalid means failed to decode.
    case remill::Instruction::kCategoryInvalid:
      VisitInvalid(inst, block);
      break;

    // Error is a valid instruction, but specifies error semantics for the
    // processor. The canonical example is x86's `UD2` instruction.
    case remill::Instruction::kCategoryError:
      VisitError(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryNormal: VisitNormal(inst, block); break;
    case remill::Instruction::kCategoryNoOp: VisitNoOp(inst, block); break;
    case remill::Instruction::kCategoryDirectJump:
      VisitDirectJump(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryIndirectJump:
      VisitIndirectJump(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryConditionalIndirectJump:
      VisitConditionalIndirectJump(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryFunctionReturn:
      VisitFunctionReturn(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryConditionalFunctionReturn:
      VisitConditionalFunctionReturn(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryDirectFunctionCall:
      VisitDirectFunctionCall(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryConditionalDirectFunctionCall:
      VisitDirectFunctionCall(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryIndirectFunctionCall:
      VisitIndirectFunctionCall(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryConditionalIndirectFunctionCall:
      VisitConditionalIndirectFunctionCall(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryConditionalBranch:
      VisitConditionalBranch(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryAsyncHyperCall:
      VisitAsyncHyperCall(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryConditionalAsyncHyperCall:
      VisitConditionalAsyncHyperCall(inst, delayed_inst, block);
      break;
  }

  // Do a second pass of annotations to apply to the control-flow branching
  // instructions added in by the above `Visit*` calls.
  AnnotateInstructions(block, pc_annotation_id, inst_annotation);

  if (delayed_inst) {
    delayed_inst->~Instruction();
  }

  curr_inst = nullptr;
}

// In the process of lifting code, we may want to call another native
// function, `native_func`, for which we have high-level type info. The main
// lifter operates on a special three-argument form function style, and
// operating on this style is actually to our benefit, as it means that as
// long as we can put data into the emulated `State` structure and pull it
// out, then calling one native function from another doesn't require /us/
// to know how to adapt one native return type into another native return
// type, and instead we let LLVM's optimizations figure it out later during
// scalar replacement of aggregates (SROA).
llvm::Value *FunctionLifter::TryCallNativeFunction(uint64_t native_addr,
                                                   llvm::Function *native_func,
                                                   llvm::BasicBlock *block) {
  auto &decl = addr_to_decl[native_addr];
  if (!decl.address) {
    auto maybe_decl = FunctionDecl::Create(*native_func, options.arch);
    if (remill::IsError(maybe_decl)) {
      LOG(ERROR) << "Unable to create FunctionDecl for "
                 << remill::LLVMThingToString(native_func->getFunctionType())
                 << " with calling convention " << native_func->getCallingConv()
                 << ": " << remill::GetErrorString(maybe_decl);
      return nullptr;
    }
    decl = std::move(remill::GetReference(maybe_decl));
  }

  llvm::IRBuilder<> irb(block);

  llvm::Value *mem_ptr = irb.CreateLoad(mem_ptr_type, mem_ptr_ref);
  mem_ptr = decl.CallFromLiftedBlock(native_func->getName().str(), intrinsics,
                                     block, state_ptr, mem_ptr, true);
  irb.SetInsertPoint(block);
  irb.CreateStore(mem_ptr, mem_ptr_ref);
  return mem_ptr;
}

// Visit all instructions. This runs the work list and lifts instructions.
void FunctionLifter::VisitInstructions(uint64_t address) {
  remill::Instruction inst;

  // Recursively decode and lift all instructions that we come across.
  while (!edge_work_list.empty()) {
    const auto [inst_addr, from_addr] = *(edge_work_list.begin());
    edge_work_list.erase(edge_work_list.begin());

    llvm::BasicBlock *const block = edge_to_dest_block[{from_addr, inst_addr}];
    DCHECK_NOTNULL(block);
    if (!block->empty()) {
      continue;  // Already handled.
    }

    // First, try to see if it's actually related to another function. This is
    // equivalent to a tail-call in the original code. This comes up with fall-
    // throughs, i.e. where one function is a prologue of another one. It also
    // happens with tail-calls, i.e. `jmp func` or `jCC func`, where we handle
    // those by way of enqueuing those addresses with `GetOrCreateTargetBlock`, and
    // then recover from the tail-calliness here, instead of spreading that
    // logic into all the control-flow visitors.
    //
    // NOTE(pag): In the case of `inst_addr == func_address && from_addr != 0`,
    //            it means we have a control-flow edge or fall-through edge
    //            back to the entrypoint of our function. In this case, treat it
    //            like a tail-call.
    if (inst_addr != func_address || from_addr) {

      auto maybe_decl = TryGetTargetFunctionType(inst_addr);
      if (maybe_decl.has_value()) {
        auto decl = maybe_decl.value();
        llvm::Function *const other_decl = DeclareFunction(decl);

        if (const auto mem_ptr_from_call =
                TryCallNativeFunction(decl.address, other_decl, block)) {
          llvm::ReturnInst::Create(llvm_context, mem_ptr_from_call, block);
          continue;
        }

        LOG(ERROR) << "Failed to call native function " << std::hex
                   << decl.address << " at " << inst_addr
                   << " via fall-through or tail call from function "
                   << func_address << std::dec;

        // NOTE(pag): Recover by falling through and just try to decode/lift
        //            the instructions.
      }
    }

    llvm::BasicBlock *&inst_block = addr_to_block[inst_addr];
    if (!inst_block) {
      inst_block = block;

    // We've already lifted this instruction via another control-flow edge.
    } else {
      llvm::BranchInst::Create(inst_block, block);
      continue;
    }

    // Decode.
    if (!DecodeInstructionInto(inst_addr, false /* is_delayed */, &inst)) {
      LOG(ERROR) << "Could not decode instruction at " << std::hex << inst_addr
                 << " reachable from instruction " << from_addr
                 << " in function at " << func_address << std::dec;
      MuteStateEscape(remill::AddTerminatingTailCall(block, intrinsics.error));
      continue;

    // Didn't get a valid instruction.
    } else if (!inst.IsValid() || inst.IsError()) {
      MuteStateEscape(remill::AddTerminatingTailCall(block, intrinsics.error));
      continue;

    } else {
      VisitInstruction(inst, block);
    }
  }
}

// Get the annotation for the program counter `pc`, or `nullptr` if we're
// not doing annotations.
llvm::MDNode *FunctionLifter::GetPCAnnotation(uint64_t pc) const {
  if (options.pc_metadata_name) {
    auto pc_val = llvm::ConstantInt::get(address_type, pc);
#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 6)
    auto pc_md = llvm::ValueAsMetadata::get(pc_val);
    return llvm::MDNode::get(llvm_context, pc_md);
#else
    return llvm::MDNode::get(llvm_context, pc_val);
#endif
  } else {
    return nullptr;
  }
}

// Declare the function decl `decl` and return an `llvm::Function *`.
llvm::Function *FunctionLifter::GetOrDeclareFunction(const FunctionDecl &decl) {

  const auto func_type = llvm::dyn_cast<llvm::FunctionType>(
      remill::RecontextualizeType(decl.type, llvm_context));

  // NOTE(pag): This may find declarations from prior lifts that have been
  //            left around in the semantics module.
  auto &native_func = addr_to_func[decl.address];
  if (native_func) {
    CHECK_EQ(native_func->getFunctionType(), func_type);
    return native_func;
  }

  // By default we do not want to deal with function names until the very end of
  // lifting. Instead, we assign a temporary name based on the function's
  // starting address, its type, and its calling convention.
  std::stringstream ss;
  ss << "sub_" << std::hex << decl.address << '_'
     << ITypeSpecification::TypeToString(
            *func_type, semantics_module->getDataLayout(), true)
     << '_' << std::dec << decl.calling_convention;

  const auto base_name = ss.str();
  func_name_to_address.emplace(base_name, decl.address);

  // Try to get it as an already named function.
  native_func = semantics_module->getFunction(base_name);
  if (native_func) {
    CHECK_EQ(native_func->getFunctionType(), func_type);
    return native_func;
  }

  native_func =
      llvm::Function::Create(func_type, llvm::GlobalValue::ExternalLinkage,
                             base_name, semantics_module.get());
  native_func->setCallingConv(decl.calling_convention);
  native_func->removeFnAttr(llvm::Attribute::InlineHint);
  native_func->removeFnAttr(llvm::Attribute::AlwaysInline);
  native_func->addFnAttr(llvm::Attribute::NoInline);
  return native_func;
}

// Allocate and initialize the state structure.
void FunctionLifter::AllocateAndInitializeStateStructure(
    llvm::BasicBlock *block) {
  llvm::IRBuilder<> ir(block);
  const auto state_type = state_ptr_type->getElementType();
  switch (options.state_struct_init_procedure) {
    case StateStructureInitializationProcedure::kNone:
      state_ptr = ir.CreateAlloca(state_type);
      break;
    case StateStructureInitializationProcedure::kZeroes:
      state_ptr = ir.CreateAlloca(state_type);
      ir.CreateStore(llvm::Constant::getNullValue(state_type), state_ptr);
      break;
    case StateStructureInitializationProcedure::kUndef:
      state_ptr = ir.CreateAlloca(state_type);
      ir.CreateStore(llvm::UndefValue::get(state_type), state_ptr);
      break;
    case StateStructureInitializationProcedure::kGlobalRegisterVariables:
      state_ptr = ir.CreateAlloca(state_type);
      InitializeStateStructureFromGlobalRegisterVariables(block);
      break;
    case StateStructureInitializationProcedure::
        kGlobalRegisterVariablesAndZeroes:
      state_ptr = ir.CreateAlloca(state_type);
      ir.CreateStore(llvm::Constant::getNullValue(state_type), state_ptr);
      InitializeStateStructureFromGlobalRegisterVariables(block);
      break;
    case StateStructureInitializationProcedure::
        kGlobalRegisterVariablesAndUndef:
      state_ptr = ir.CreateAlloca(state_type);
      ir.CreateStore(llvm::UndefValue::get(state_type), state_ptr);
      InitializeStateStructureFromGlobalRegisterVariables(block);
      break;
  }

  ArchSpecificStateStructureInitialization(block);
}

// Perform architecture-specific initialization of the state structure
// in `block`.
void FunctionLifter::ArchSpecificStateStructureInitialization(
    llvm::BasicBlock *block) {

  if (is_x86_or_amd64) {
    llvm::IRBuilder<> ir(block);

    const auto ssbase_reg = options.arch->RegisterByName("SSBASE");
    const auto fsbase_reg = options.arch->RegisterByName("FSBASE");
    const auto gsbase_reg = options.arch->RegisterByName("GSBASE");

    if (gsbase_reg) {
      const auto gsbase_val =
          llvm::ConstantExpr::getPtrToInt(
              llvm::ConstantExpr::getAddrSpaceCast(
                  llvm::ConstantExpr::getNullValue(
                      llvm::PointerType::get(i8_type, 256)),
                  llvm::PointerType::get(i8_type, 0)),
              pc_reg_type);
      ir.CreateStore(gsbase_val, gsbase_reg->AddressOf(state_ptr, ir));
    }

    if (fsbase_reg) {
      const auto fsbase_val =
          llvm::ConstantExpr::getPtrToInt(
              llvm::ConstantExpr::getAddrSpaceCast(
                  llvm::ConstantExpr::getNullValue(
                      llvm::PointerType::get(i8_type, 257)),
                  llvm::PointerType::get(i8_type, 0)),
              pc_reg_type);
      ir.CreateStore(fsbase_val, fsbase_reg->AddressOf(state_ptr, ir));
    }

    if (ssbase_reg) {
      ir.CreateStore(llvm::Constant::getNullValue(pc_reg_type),
                     ssbase_reg->AddressOf(state_ptr, ir));
    }
  }
}

// Initialize the state structure with default values, loaded from global
// variables. The purpose of these global variables is to show that there are
// some unmodelled external dependencies inside of a lifted function.
void FunctionLifter::InitializeStateStructureFromGlobalRegisterVariables(
    llvm::BasicBlock *block) {

  // Get or create globals for all top-level registers. The idea here is that
  // the spec could feasibly miss some dependencies, and so after optimization,
  // we'll be able to observe uses of `__anvill_reg_*` globals, and handle
  // them appropriately.

  llvm::IRBuilder<> ir(block);

  options.arch->ForEachRegister([=, &ir](const remill::Register *reg_) {
    if (auto reg = reg_->EnclosingRegister(); reg_ == reg) {

      // If we're going to lift the stack frame, then don't store something
      // like `__anvill_reg_RSP`, otherwise that might confuse later stack
      // frame recovery (especially if there's an issue eliminating the `State`
      // structure).
      if (options.symbolic_stack_pointer &&
          reg->name == options.arch->StackPointerRegisterName()) {
        return;
      }

      std::stringstream ss;
      ss << kUnmodelledRegisterPrefix << reg->name;
      const auto reg_name = ss.str();

      auto reg_global = semantics_module->getGlobalVariable(reg_name);
      if (!reg_global) {
        reg_global = new llvm::GlobalVariable(
            *semantics_module, reg->type, false,
            llvm::GlobalValue::ExternalLinkage, nullptr, reg_name);
      }

      const auto reg_ptr = reg->AddressOf(state_ptr, block);
      ir.CreateStore(ir.CreateLoad(reg_global), reg_ptr);
    }
  });
}

llvm::Value *FunctionLifter::GenerateProgramCounter(llvm::BasicBlock *block,
                                                    std::uint64_t address) {
  if (options.symbolic_program_counter) {
    return GenerateSymbolicProgramCounter(block, address);
  } else {
    return GenerateConcreteProgramCounter(block, address);
  }
}

void FunctionLifter::UpdateProgramCounter(llvm::BasicBlock *block,
                                          llvm::Value *pc) {
  auto pc_reg =
      options.arch->RegisterByName(options.arch->ProgramCounterRegisterName());

  auto pc_reg_ptr = pc_reg->AddressOf(state_ptr, block);

  llvm::IRBuilder<> ir(block);
  ir.CreateStore(pc, pc_reg_ptr);
}

llvm::Value *
FunctionLifter::GenerateSymbolicProgramCounter(llvm::BasicBlock *block,
                                               std::uint64_t address) {
  auto base_pc = semantics_module->getGlobalVariable(kSymbolicPCName);
  if (!base_pc) {
    base_pc = new llvm::GlobalVariable(*semantics_module, i8_type, false,
                                       llvm::GlobalValue::ExternalLinkage,
                                       i8_zero, kSymbolicPCName);
  }

  auto pc = llvm::ConstantExpr::getAdd(
      llvm::ConstantExpr::getPtrToInt(base_pc, pc_reg_type),
      llvm::ConstantInt::get(pc_reg_type, address, false));

  return pc;
}

// Initialize a symbolic program counter value in a lifted function. This
// mechanism is used to improve cross-reference discovery by using a
// relocatable constant expression as the initial value for a program counter.
// After optimizations, the net effect is that anything derived from this
// initial program counter is "tainted" by this initial constant expression,
// and therefore can be found.
llvm::Value *
FunctionLifter::InitializeSymbolicProgramCounter(llvm::BasicBlock *block) {
  auto pc = GenerateSymbolicProgramCounter(block, func_address);
  UpdateProgramCounter(block, pc);

  return pc;
}

llvm::Value *
FunctionLifter::GenerateConcreteProgramCounter(llvm::BasicBlock *block,
                                               std::uint64_t address) {
  auto pc = llvm::ConstantInt::get(pc_reg_type, address, false);
  return pc;
}

llvm::Value *
FunctionLifter::InitializeConcreteProgramCounter(llvm::BasicBlock *block) {
  auto pc = GenerateConcreteProgramCounter(block, func_address);
  UpdateProgramCounter(block, pc);

  return pc;
}

// Initialize a symbolic stack pointer value in a lifted function. This
// mechanism is used to improve stack frame recovery, in a similar way that
// a symbolic PC improves cross-reference discovery.
void FunctionLifter::InitializeSymbolicStackPointer(llvm::BasicBlock *block) {
  auto sp_reg =
      options.arch->RegisterByName(options.arch->StackPointerRegisterName());

  auto sp_reg_ptr = sp_reg->AddressOf(state_ptr, block);

  auto base_sp = semantics_module->getGlobalVariable(kSymbolicSPName);
  if (!base_sp) {
    base_sp = new llvm::GlobalVariable(*semantics_module, i8_type, false,
                                       llvm::GlobalValue::ExternalLinkage,
                                       i8_zero, kSymbolicSPName);
  }

  auto sp = llvm::ConstantExpr::getPtrToInt(base_sp, sp_reg->type);
  llvm::IRBuilder<> ir(block);
  ir.CreateStore(sp, sp_reg_ptr);
}

// Initialize a symbolic return address. This is similar to symbolic program
// counters/stack pointers.
llvm::Value *
FunctionLifter::InitializeSymbolicReturnAddress(llvm::BasicBlock *block,
                                                llvm::Value *mem_ptr,
                                                const ValueDecl &ret_address) {
  auto base_ra = semantics_module->getGlobalVariable(kSymbolicRAName);
  if (!base_ra) {
    base_ra = new llvm::GlobalVariable(*semantics_module, i8_type, false,
                                       llvm::GlobalValue::ExternalLinkage,
                                       i8_zero, kSymbolicRAName);
  }

  auto pc_reg =
      options.arch->RegisterByName(options.arch->ProgramCounterRegisterName());
  auto ret_addr = llvm::ConstantExpr::getPtrToInt(base_ra, pc_reg->type);

  return StoreNativeValue(ret_addr, ret_address, intrinsics, block, state_ptr,
                          mem_ptr);
}

// Initialize a concrete return address. This is an intrinsic function call.
llvm::Value *
FunctionLifter::InitializeConcreteReturnAddress(llvm::BasicBlock *block,
                                                llvm::Value *mem_ptr,
                                                const ValueDecl &ret_address) {
  auto ret_addr_func = llvm::Intrinsic::getDeclaration(
      semantics_module.get(), llvm::Intrinsic::returnaddress);
  llvm::Value *args[] = {llvm::ConstantInt::get(i32_type, 0)};

  auto pc_reg =
      options.arch->RegisterByName(options.arch->ProgramCounterRegisterName());

  llvm::Value *ret_addr =
      llvm::CallInst::Create(ret_addr_func, args, llvm::None,
                             llvm::Twine::createNull(), &(block->front()));

  llvm::IRBuilder<> ir(block);
  ret_addr =
      ir.CreatePtrToInt(ret_addr, pc_reg->type, llvm::Twine::createNull());
  return StoreNativeValue(ret_addr, ret_address, intrinsics, block, state_ptr,
                          mem_ptr);
}

// Set up `native_func` to be able to call `lifted_func`. This means
// marshalling high-level argument types into lower-level values to pass into
// a stack-allocated `State` structure. This also involves providing initial
// default values for registers.
void FunctionLifter::CallLiftedFunctionFromNativeFunction(
    const FunctionDecl &decl) {
  if (!native_func->isDeclaration()) {
    return;
  }

  // Get a `FunctionDecl` for `native_func`, which we can use to figure out
  // how to marshal its parameters into the emulated `State` and `Memory *`
  // of Remill lifted code, and marshal out the return value, if any.
  auto &native_decl = addr_to_decl[func_address];
  if (!native_decl.address) {
    auto maybe_decl = FunctionDecl::Create(*native_func, options.arch);
    if (remill::IsError(maybe_decl)) {
      LOG(ERROR) << "Unable to create FunctionDecl for "
                 << remill::LLVMThingToString(native_func->getFunctionType())
                 << " with calling convention " << native_func->getCallingConv()
                 << ": " << remill::GetErrorString(maybe_decl);
      return;
    }

    native_decl = std::move(remill::GetReference(maybe_decl));
  }

  // Create a state structure and a stack frame in the native function
  // and we'll call the lifted function with that. The lifted function
  // will get inlined into this function.
  auto block = llvm::BasicBlock::Create(llvm_context, "", native_func);

  // Create a memory pointer.
  llvm::Value *mem_ptr = llvm::Constant::getNullValue(mem_ptr_type);

  // Stack-allocate and initialize the state pointer.
  AllocateAndInitializeStateStructure(block);

  llvm::Value *pc = nullptr;
  if (options.symbolic_program_counter) {
    pc = InitializeSymbolicProgramCounter(block);
  } else {
    pc = InitializeConcreteProgramCounter(block);
  }

  // Initialize the stack pointer.
  if (options.symbolic_stack_pointer) {
    InitializeSymbolicStackPointer(block);
  }

  // Put the function's return address wherever it needs to go.
  if (decl.has_return_address) {
    if (options.symbolic_return_address) {
      mem_ptr = InitializeSymbolicReturnAddress(block, mem_ptr,
                                                native_decl.return_address);
    } else {
      mem_ptr = InitializeConcreteReturnAddress(block, mem_ptr,
                                                native_decl.return_address);
    }
  }

  // Store the function parameters either into the state struct
  // or into memory (likely the stack).
  auto arg_index = 0u;
  for (auto &arg : native_func->args()) {
    const auto &param_decl = native_decl.params[arg_index++];
    mem_ptr = StoreNativeValue(&arg, param_decl, intrinsics, block, state_ptr,
                               mem_ptr);
  }

  llvm::IRBuilder<> ir(block);

  llvm::Value *lifted_func_args[remill::kNumBlockArgs] = {};
  lifted_func_args[remill::kStatePointerArgNum] = state_ptr;
  lifted_func_args[remill::kMemoryPointerArgNum] = mem_ptr;
  lifted_func_args[remill::kPCArgNum] = pc;
  auto call_to_lifted_func = ir.CreateCall(lifted_func, lifted_func_args);
  mem_ptr = call_to_lifted_func;

  // Annotate all instructions leading up to and including the call of the
  // lifted function using the function's address.
  //
  // NOTE(pag): We don't annotate any of the subsequently created instructions
  //            for marshalling return values back out because there may be
  //            multiple return/tail-call sites in the function we've just
  //            lifted.
  AnnotateInstructions(block, pc_annotation_id,
                       GetPCAnnotation(func_address));

  llvm::Value *ret_val = nullptr;

  if (native_decl.returns.size() == 1) {
    ret_val = LoadLiftedValue(native_decl.returns.front(), intrinsics, block,
                              state_ptr, mem_ptr);
    ir.SetInsertPoint(block);

  } else if (1 < native_decl.returns.size()) {
    ret_val = llvm::UndefValue::get(native_func->getReturnType());
    auto index = 0u;
    for (auto &ret_decl : native_decl.returns) {
      auto partial_ret_val =
          LoadLiftedValue(ret_decl, intrinsics, block, state_ptr, mem_ptr);
      ir.SetInsertPoint(block);
      unsigned indexes[] = {index};
      ret_val = ir.CreateInsertValue(ret_val, partial_ret_val, indexes);
      index += 1;
    }
  }

  auto memory_escape = GetMemoryEscapeFunc(intrinsics);
  llvm::Value *escape_args[] = {mem_ptr};
  ir.CreateCall(memory_escape, escape_args);

  if (ret_val) {
    ir.CreateRet(ret_val);
  } else {
    ir.CreateRetVoid();
  }
}

// In practice, lifted functions are not workable as is; we need to emulate
// `__attribute__((flatten))`, i.e. recursively inline as much as possible, so
// that all semantics and helpers are completely inlined.
void FunctionLifter::RecursivelyInlineLiftedFunctionIntoNativeFunction(void) {
  std::vector<llvm::CallInst *> calls_to_inline;

  // Set of instructions that we should not annotate because we can't tie them
  // to a particular instruction address.
  std::unordered_set<llvm::Instruction *> insts_without_provenance;
  if (options.pc_metadata_name) {
    for (auto &inst : llvm::instructions(*native_func)) {
      if (!inst.getMetadata(pc_annotation_id)) {
        insts_without_provenance.insert(&inst);
      }
    }
  }

  for (auto changed = true; changed; changed = !calls_to_inline.empty()) {
    calls_to_inline.clear();

    for (auto &inst : llvm::instructions(*native_func)) {
      if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst); call_inst) {
        if (auto called_func = call_inst->getCalledFunction();
            called_func && !called_func->isDeclaration() &&
            !called_func->hasFnAttribute(llvm::Attribute::NoInline)) {
          calls_to_inline.push_back(call_inst);
        }
      }
    }

    for (llvm::CallInst *call_inst : calls_to_inline) {
      llvm::MDNode *call_pc = nullptr;
      if (options.pc_metadata_name) {
        call_pc = call_inst->getMetadata(pc_annotation_id);
      }

      llvm::InlineFunctionInfo info;
      InlineFunction(call_inst, info);

      // Propagate PC metadata from call sites into inlined call bodies.
      if (options.pc_metadata_name) {
        for (auto &inst : llvm::instructions(*native_func)) {
          if (!inst.getMetadata(pc_annotation_id)) {
            if (insts_without_provenance.count(&inst)) {
              continue;

            // This call site had no associated PC metadata, and so we want
            // to exclude any inlined code from accidentally being associated
            // with other PCs on future passes.
            } else if (!call_pc) {
              insts_without_provenance.insert(&inst);

            // We can propagate the annotation.
            } else {
              inst.setMetadata(pc_annotation_id, call_pc);
            }
          }
        }
      }
    }
  }

  // Initialize cleanup optimizations
  llvm::legacy::FunctionPassManager fpm(semantics_module.get());
  fpm.add(llvm::createCFGSimplificationPass());
  fpm.add(llvm::createPromoteMemoryToRegisterPass());
  fpm.add(llvm::createReassociatePass());
  fpm.add(llvm::createDeadStoreEliminationPass());
  fpm.add(llvm::createDeadCodeEliminationPass());
  fpm.add(llvm::createSROAPass());
  fpm.add(llvm::createDeadCodeEliminationPass());
  fpm.add(llvm::createInstructionCombiningPass());
  fpm.doInitialization();
  fpm.run(*native_func);
  fpm.doFinalization();

  ClearVariableNames(native_func);
}

// Lift a function. Will return `nullptr` if the memory is
// not accessible or executable.
llvm::Function *FunctionLifter::DeclareFunction(const FunctionDecl &decl) {

  // Not a valid address, or memory isn't executable.
  auto [first_byte, first_byte_avail, first_byte_perms] =
      memory_provider.Query(decl.address);
  if (!MemoryProvider::IsValidAddress(first_byte_avail) ||
      !MemoryProvider::IsExecutable(first_byte_perms)) {
    return nullptr;
  }

  // This is our higher-level function, i.e. it presents itself more like
  // a function compiled from C/C++, rather than being a three-argument Remill
  // function. In this function, we will stack-allocate a `State` structure,
  // then call a `lifted_func` below, which will embed the instruction
  // semantics.
  return GetOrDeclareFunction(decl);
}

// Lift a function. Will return `nullptr` if the memory is
// not accessible or executable.
llvm::Function *FunctionLifter::LiftFunction(const FunctionDecl &decl) {

  addr_to_decl.clear();
  addr_to_func.clear();
  edge_work_list.clear();
  edge_to_dest_block.clear();
  addr_to_block.clear();
  inst_lifter.ClearCache();
  curr_inst = nullptr;
  state_ptr = nullptr;
  mem_ptr_ref = nullptr;
  func_address = decl.address;
  native_func = DeclareFunction(decl);

  // Not a valid address, or memory isn't executable.
  auto [first_byte, first_byte_avail, first_byte_perms] =
      memory_provider.Query(func_address);
  if (!MemoryProvider::IsValidAddress(first_byte_avail) ||
      !MemoryProvider::IsExecutable(first_byte_perms)) {
    return nullptr;
  }

  // This is our higher-level function, i.e. it presents itself more like
  // a function compiled from C/C++, rather than being a three-argument Remill
  // function. In this function, we will stack-allocate a `State` structure,
  // then call a `lifted_func` below, which will embed the instruction
  // semantics.
  native_func = GetOrDeclareFunction(decl);

  // Check if we already lifted this function. If so, do not re-lift it.
  if (!native_func->isDeclaration()) {
    return native_func;
  }

  // The address is valid, the memory is executable, but we don't actually have
  // the data available for lifting, so leave us with just a declaration.
  if (!MemoryProvider::HasByte(first_byte_avail)) {
    return native_func;
  }

  // Every lifted function starts as a clone of __remill_basic_block. That
  // prototype has multiple arguments (memory pointer, state pointer, program
  // counter). This extracts the state pointer.
  lifted_func = remill::DeclareLiftedFunction(
      semantics_module.get(), native_func->getName().str() + ".lifted");

  state_ptr = remill::NthArgument(lifted_func, remill::kStatePointerArgNum);
  CHECK(lifted_func->isDeclaration());

  remill::CloneBlockFunctionInto(lifted_func);
  lifted_func->removeFnAttr(llvm::Attribute::NoInline);
  lifted_func->addFnAttr(llvm::Attribute::InlineHint);
  lifted_func->addFnAttr(llvm::Attribute::AlwaysInline);
  lifted_func->setLinkage(llvm::GlobalValue::InternalLinkage);

  const auto pc = remill::NthArgument(lifted_func, remill::kPCArgNum);
  const auto entry_block = &(lifted_func->getEntryBlock());
  const auto pc_ptr = inst_lifter.LoadRegAddress(entry_block, state_ptr,
                                                 remill::kPCVariableName);
  const auto next_pc_ptr = inst_lifter.LoadRegAddress(
      entry_block, state_ptr, remill::kNextPCVariableName);

  mem_ptr_ref = remill::LoadMemoryPointerRef(entry_block);

  // Force initialize both the `PC` and `NEXT_PC` from the `pc` argument.
  // On some architectures, `NEXT_PC` is a "pseudo-register", i.e. an `alloca`
  // inside of `__remill_basic_block`, of which `lifted_func` is a clone, and
  // so we want to ensure it gets reliably initialized before any lifted
  // instructions may depend upon it.
  llvm::IRBuilder<> ir(entry_block);
  ir.CreateStore(pc, next_pc_ptr);
  ir.CreateStore(pc, pc_ptr);

  // Add a branch between the first block of the lifted function, which sets
  // up some local variables, and the block that will contain the lifted
  // instruction.
  //
  // NOTE(pag): This also introduces the first element to the work list.
  //
  // TODO: This could be a thunk, that we are maybe lifting on purpose.
  //       How should control flow redirection behave in this case?
  ir.CreateBr(GetOrCreateBlock(func_address));

  AnnotateInstructions(entry_block, pc_annotation_id,
                       GetPCAnnotation(func_address));

  // Go lift all instructions!
  VisitInstructions(func_address);

  // Fill up `native_func` with a basic block and make it call `lifted_func`.
  // This creates things like the stack-allocated `State` structure.
  CallLiftedFunctionFromNativeFunction(decl);

  // The last stage is that we need to recursively inline all calls to semantics
  // functions into `native_func`.
  RecursivelyInlineLiftedFunctionIntoNativeFunction();

  return native_func;
}

// Returns the address of a named function.
std::optional<uint64_t>
FunctionLifter::AddressOfNamedFunction(const std::string &func_name) const {
  auto it = func_name_to_address.find(func_name);
  if (it == func_name_to_address.end()) {
    return std::nullopt;
  } else {
    return it->second;
  }
}

// Lifts the machine code function starting at address `decl.address`, and
// using the architecture of the lifter context, lifts the bytes into the
// context's module.
//
// Returns an `llvm::Function *` that is part of `options_.module`.
//
// NOTE(pag): If this function returns `nullptr` then it means that we cannot
//            lift the function (e.g. bad address, or non-executable memory).
llvm::Function *EntityLifter::LiftEntity(const FunctionDecl &decl) const {
  auto &func_lifter = impl->function_lifter;
  llvm::Module *const module = impl->options.module;
  llvm::LLVMContext &context = module->getContext();
  llvm::FunctionType *module_func_type = llvm::dyn_cast<llvm::FunctionType>(
      remill::RecontextualizeType(decl.type, context));
  llvm::Function *found_by_type = nullptr;
  llvm::Function *found_by_address = nullptr;

  // Go try to figure out if we've already got a declaration for this specific
  // function at the corresponding address.
  impl->ForEachEntityAtAddress(decl.address, [&](llvm::Constant *gv) {
    if (auto func = llvm::dyn_cast<llvm::Function>(gv)) {
      if (func->getFunctionType() == module_func_type) {
        found_by_type = func;

      } else if (!found_by_address) {
        found_by_address = func;
      }
    }
  });

  LOG_IF(ERROR, found_by_address != nullptr)
      << "Ignoring existing version of function at address " << std::hex
      << decl.address << " with type "
      << remill::LLVMThingToString(found_by_address->getFunctionType())
      << " and lifting function with type "
      << remill::LLVMThingToString(module_func_type);

  // Try to lift the function. If we failed then return the function found
  // with a matching type, if any.
  const auto func = func_lifter.LiftFunction(decl);
  if (!func) {
    return found_by_type;
  }

  // Make sure the names match up so that when we copy `func` into
  // `options.module`, we end up copying into the right function.
  std::string old_name;
  if (found_by_type && found_by_type->getName() != func->getName()) {
    old_name = found_by_type->getName().str();
    found_by_type->setName(func->getName());
  }

  // Add the function to the entity lifter's target module.
  const auto func_in_target_module =
      func_lifter.AddFunctionToContext(func, decl.address, *impl);

  // If we had a previous declaration/definition, then we want to make sure
  // that we replaced its body, and we also want to make sure that if our
  // default function naming scheme is not using the same name as the function
  // then we fixup its name to be its prior name. This could happen if the
  // user renames a function between lifts/declares.
  if (found_by_type) {
    CHECK_EQ(func_in_target_module, found_by_type);
    if (!old_name.empty() && func_in_target_module->getName() != old_name) {
      func_in_target_module->setName(old_name);
    }
  }

  return func_in_target_module;
}

// Declare the function associated with `decl` in the context's module.
//
// NOTE(pag): If this function returns `nullptr` then it means that we cannot
//            declare the function (e.g. bad address, or non-executable
//            memory).
llvm::Function *EntityLifter::DeclareEntity(const FunctionDecl &decl) const {
  auto &func_lifter = impl->function_lifter;
  llvm::Module *const module = impl->options.module;
  llvm::LLVMContext &context = module->getContext();
  llvm::FunctionType *module_func_type = llvm::dyn_cast<llvm::FunctionType>(
      remill::RecontextualizeType(decl.type, context));

  llvm::Function *found_by_type = nullptr;
  llvm::Function *found_by_address = nullptr;

  // Go try to figure out if we've already got a declaration for this specific
  // function at the corresponding address.
  //
  // TODO(pag): Refactor out this copypasta.
  impl->ForEachEntityAtAddress(decl.address, [&](llvm::Constant *gv) {
    if (auto func = llvm::dyn_cast<llvm::Function>(gv)) {
      if (func->getFunctionType() == module_func_type) {
        found_by_type = func;

      } else if (!found_by_address) {
        found_by_address = func;
      }
    }
  });

  // We've already got a declaration for this function; return it.
  if (found_by_type) {
    return found_by_type;
  }

  LOG_IF(ERROR, found_by_address != nullptr)
      << "Ignoring existing version of function at address " << std::hex
      << decl.address << " with type "
      << remill::LLVMThingToString(found_by_address->getFunctionType())
      << " and declaring function with type "
      << remill::LLVMThingToString(module_func_type);

  if (const auto func = func_lifter.DeclareFunction(decl)) {
    DCHECK(!module->getFunction(func->getName()));
    return func_lifter.AddFunctionToContext(func, decl.address, *impl);
  } else {
    return nullptr;
  }
}

namespace {

// Erase the body of a function.
static void EraseFunctionBody(llvm::Function *func) {
  std::vector<llvm::BasicBlock *> blocks_to_erase;
  std::vector<llvm::Instruction *> insts_to_erase;

  // Collect stuff for erasure.
  for (auto &block : *func) {
    block.dropAllReferences();
  }

  while (!func->isDeclaration()) {
    func->back().eraseFromParent();
  }
}

}  // namespace

// Update the associated entity lifter with information about this
// function, and copy the function into the context's module. Returns the
// version of `func` inside the module of the lifter context.
llvm::Function *
FunctionLifter::AddFunctionToContext(llvm::Function *func, uint64_t address,
                                     EntityLifterImpl &lifter_context) const {

  const auto target_module = options.module;
  auto &module_context = target_module->getContext();
  const auto name = func->getName().str();
  const auto module_func_type = llvm::dyn_cast<llvm::FunctionType>(
      remill::RecontextualizeType(func->getFunctionType(), module_context));

  // Try to get the old version of the function by name. If it exists and has
  // a body then erase it. As much as possible, we want to maintain referential
  // transparency w.r.t. user code, and not suddenly delete things out from
  // under them.
  auto new_version = target_module->getFunction(name);
  if (new_version) {
    CHECK_EQ(module_func_type, new_version->getFunctionType());
    if (!new_version->isDeclaration()) {
      EraseFunctionBody(new_version);
      CHECK(new_version->isDeclaration());
    }

  // It's possible that we've lifted this function before, but that it was
  // renamed by user code, and so the above check failed. Go check for that.
  } else {
    lifter_context.ForEachEntityAtAddress(address, [&](llvm::Constant *gv) {
      if (auto gv_func = llvm::dyn_cast<llvm::Function>(gv);
          gv_func && gv_func->getFunctionType() == module_func_type) {
        CHECK(!new_version);
        new_version = gv_func;
      }
    });
  }

  // This is the first time we're lifting this function, or even the first time
  // we're seeing a reference to it, so we will need to make the function in
  // the target module.
  if (!new_version) {
    new_version = llvm::Function::Create(module_func_type,
                                         llvm::GlobalValue::ExternalLinkage,
                                         name, target_module);
  }

  remill::CloneFunctionInto(func, new_version);

  // Now that we're done, erase the body of `func`. We keep `func` around
  // just in case it will be needed in future lifts.
  EraseFunctionBody(func);

  // Update the context to keep its internal concepts of what LLVM objects
  // correspond with which native binary addresses.
  lifter_context.AddEntity(new_version, address);

  // The function we just lifted may call other functions, so we need to go
  // find those and also use them to update the context.
  for (auto &inst : llvm::instructions(*func)) {
    if (auto call = llvm::dyn_cast<llvm::CallBase>(&inst)) {
      if (auto called_func = call->getCalledFunction()) {
        const auto called_func_name = called_func->getName().str();
        auto called_func_addr = AddressOfNamedFunction(called_func_name);
        if (called_func_addr) {
          lifter_context.AddEntity(called_func, *called_func_addr);
        }
      }
    }
  }

  return new_version;
}

}  // namespace anvill
