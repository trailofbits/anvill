/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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

#include <anvill/Analysis/Utils.h>
#include <anvill/Analysis/CrossReferenceResolver.h>
#include <anvill/Transforms.h>
#include <glog/logging.h>
#include <llvm/ADT/Triple.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>

#include <utility>
#include <vector>

namespace anvill {
namespace {

enum ReturnAddressResult {

  // We've found a case where a value returned by `llvm.returnaddress`, or
  // casted from `__anvill_ra`, reaches into the `pc` argument of the
  // `__remill_function_return` intrinsic. This is the ideal case that we
  // want to handle.
  kFoundReturnAddress,

  // We've found a case where we're seeing a load from something derived from
  // `__anvill_sp`, our "symbolic stack pointer", is reaching into the `pc`
  // argument of `__remill_function_return`. This suggests that stack frame
  // recovery has not happened yet, and thus we haven't really given stack
  // frame recovery or stack frame splitting a chance to work.
  kFoundSymbolicStackPointerLoad,

  // We've found a `load` or something else. This is probably a sign that
  // stack frame recovery has happened, and that the actual return address
  // is not necessarily the expected value, and so we need to try to swap
  // out the return address with whatever we loaded.
  kUnclassifiableReturnAddress
};

class RemoveRemillFunctionReturns final : public llvm::FunctionPass {
 public:
  RemoveRemillFunctionReturns(const EntityLifter &lifter_)
      : llvm::FunctionPass(ID),
        xref_resolver(lifter_) {}

  bool runOnFunction(llvm::Function &func) final;

 private:
  ReturnAddressResult QueryReturnAddress(llvm::Module *module,
                                         llvm::Value *val) const;

  static char ID;
  const CrossReferenceResolver xref_resolver;
};

char RemoveRemillFunctionReturns::ID = '\0';

// Returns `true` if `val` is a return address.
ReturnAddressResult RemoveRemillFunctionReturns::QueryReturnAddress(
    llvm::Module *module, llvm::Value *val) const {

  if (IsReturnAddress(module, val)) {
    return kFoundReturnAddress;
  }

  if (auto call = llvm::dyn_cast<llvm::CallBase>(val)) {
    if (auto func = call->getCalledFunction()) {
      if (func->getName().startswith("__remill_read_memory_")) {
        auto addr = call->getArgOperand(1);  // Address
        if (IsRelatedToStackPointer(module, addr)) {
          return kFoundSymbolicStackPointerLoad;
        } else {
          return kUnclassifiableReturnAddress;
        }
      }
    }
    return kUnclassifiableReturnAddress;

  } else if (auto li = llvm::dyn_cast<llvm::LoadInst>(val)) {
    if (IsRelatedToStackPointer(module, li->getPointerOperand())) {
      return kFoundSymbolicStackPointerLoad;
    } else {
      return kUnclassifiableReturnAddress;
    }

  } else if (auto pti = llvm::dyn_cast<llvm::PtrToIntOperator>(val)) {
    return QueryReturnAddress(module, pti->getOperand(0));

  } else if (auto cast = llvm::dyn_cast<llvm::CastInst>(val)) {
    return QueryReturnAddress(module, cast->getOperand(0));

  } else if (IsRelatedToStackPointer(module, val)) {
    return kFoundSymbolicStackPointerLoad;

  // Sometimes optimizations result in really crazy looking constant expressions
  // related to `__anvill_ra`, full of shifts, zexts, etc. We try to detect
  // this situation by initializing a "magic" address associated with
  // `__anvill_ra`, and then if we find this magic value on something that
  // references `__anvill_ra`, then we conclude that all those manipulations
  // in the constant expression are actually not important.
  } else if (auto xr = xref_resolver.TryResolveReference(val);
             xr.is_valid && xr.references_return_address &&
             xr.u.address == xref_resolver.MagicReturnAddressValue()) {
    return kFoundReturnAddress;

  } else {
    return kUnclassifiableReturnAddress;
  }
}

// Remove a single case of a call to `__remill_function_return` where the return
// addresses reaches the `pc` argument of the call.
static void FoldReturnAddressMatch(llvm::CallBase *call) {
  auto module = call->getModule();
  auto ret_addr =
      llvm::dyn_cast<llvm::Instruction>(call->getArgOperand(remill::kPCArgNum));
  auto mem_ptr = call->getArgOperand(remill::kMemoryPointerArgNum);
  call->replaceAllUsesWith(mem_ptr);
  call->eraseFromParent();

  // Work up the use list of casts back to the source of this return
  // address, eliminating as many of those values as possible.
  while (ret_addr && ret_addr->use_empty()) {

    // Cast of `llvm.returnaddress`.
    if (auto cast_inst = llvm::dyn_cast<llvm::CastInst>(ret_addr)) {
      auto next_ret_addr =
          llvm::dyn_cast<llvm::Instruction>(cast_inst->getOperand(0));
      ret_addr->eraseFromParent();
      ret_addr = next_ret_addr;

    // Call to `llvm.returnaddress`.
    } else if (IsReturnAddress(module, ret_addr)) {
      ret_addr->eraseFromParent();
      break;

    // Who knows?!
    } else {
      LOG(ERROR)
          << "Encountered unexpected instruction when removing return address: "
          << remill::LLVMThingToString(ret_addr);
      break;
    }
  }
}

// Returns the pointer to the function that lets us overwrite the return
// address. This is not available on all architectures / OSes.
static llvm::Function *AddressOfReturnAddressFunction(llvm::Module *module) {
  llvm::Triple triple(module->getTargetTriple());
  const char *func_name = nullptr;
  switch (triple.getArch()) {
    case llvm::Triple::ArchType::x86:
    case llvm::Triple::ArchType::x86_64:
    case llvm::Triple::ArchType::aarch64:
    case llvm::Triple::ArchType::aarch64_be:
      func_name = "llvm.addressofreturnaddress.p0i8";
      break;

    // The Windows `_AddressOfReturnAddress` intrinsic function works on
    // AArch32 / ARMv7 (as well as the above).
    case llvm::Triple::ArchType::arm:
    case llvm::Triple::ArchType::armeb:
    case llvm::Triple::ArchType::aarch64_32:
      if (triple.isOSWindows()) {
        func_name = "_AddressOfReturnAddress";
      }
      break;
    default: break;
  }

  llvm::Function *func = nullptr;

  // Common path to handle the Windows-specific case, or the slightly
  // more general case uniformly.
  if (func_name) {
    func = module->getFunction(func_name);
    if (!func) {
      auto &context = module->getContext();
      auto fty =
          llvm::FunctionType::get(llvm::Type::getInt8PtrTy(context, 0), false);
      func = llvm::Function::Create(fty, llvm::GlobalValue::ExternalLinkage,
                                    func_name, module);
    }
  }

  return func;
}

// Override the return address in the function `func` with values from
// `fixups`.
static void OverwriteReturnAddress(
    llvm::Function &func, llvm::Function *addr_of_ret_addr_func,
    std::vector<std::pair<llvm::CallBase *, llvm::Value *>> &fixups) {

  // Get the address of our return address.
  const auto addr_of_ret_addr = llvm::CallInst::Create(
      addr_of_ret_addr_func, {}, llvm::None, llvm::Twine::createNull(),
      &(func.getEntryBlock().front()));

  for (auto &[call, ret_addr] : fixups) {
    auto ret_addr_type = ret_addr->getType();

    // Store the return address.
    llvm::IRBuilder<> ir(call);
    ir.CreateStore(ret_addr,
                   ir.CreateBitCast(addr_of_ret_addr,
                                    llvm::PointerType::get(ret_addr_type, 0)));

    // Get rid of the `__remill_function_return`.
    call->replaceAllUsesWith(call->getArgOperand(remill::kMemoryPointerArgNum));
    call->eraseFromParent();
  }
}

// Try to identify the patterns of `__remill_function_call` that we can
// remove.
bool RemoveRemillFunctionReturns::runOnFunction(llvm::Function &func) {

  const auto module = func.getParent();
  std::vector<llvm::CallBase *> matches_pattern;
  std::vector<std::pair<llvm::CallBase *, llvm::Value *>> fixups;

  for (auto &inst : llvm::instructions(func)) {
    if (auto call = llvm::dyn_cast<llvm::CallBase>(&inst)) {
      if (auto func = call->getCalledFunction();
          func && func->getName() == "__remill_function_return") {
        auto ret_addr = call->getArgOperand(remill::kPCArgNum)
                            ->stripPointerCastsAndAliases();
        switch (QueryReturnAddress(module, ret_addr)) {
          case kFoundReturnAddress: matches_pattern.push_back(call); break;

          // Do nothing if it's a symbolic stack pointer load; we're probably
          // running this pass too early.
          case kFoundSymbolicStackPointerLoad: break;

          // Here we'll do an arch-specific fixup.
          case kUnclassifiableReturnAddress:
            fixups.emplace_back(call, ret_addr);
            break;
        }
      }
    }
  }

  auto ret = false;

  // Go remove all the matches that we can.
  for (auto call : matches_pattern) {
    FoldReturnAddressMatch(call);
    ret = true;
  }

  // Go use the `llvm.addressofreturnaddress` to store replace the return
  // address.
  if (!fixups.empty()) {
    if (auto addr_of_ret_addr_func = AddressOfReturnAddressFunction(module)) {
      OverwriteReturnAddress(func, addr_of_ret_addr_func, fixups);
      ret = true;
    }
  }

  return ret;
}

}  // namespace

// Transforms the bitcode to eliminate calls to `__remill_function_return`,
// where appropriate. This will not succeed for all architectures, but is
// likely to always succeed for x86(-64) and aarch64, due to their support
// for the `llvm.addressofreturnaddress` intrinsic.
//
// When we lift bitcode, we represent the control-flow transfer semantics of
// function returns with calls to `__remill_function_return`. This is another
// three-argument Remill function, where the second argument is the program
// counter. We're particularly interested in observing this program counter
// value, as it can tell us if this function respects normal return conventions
// (i.e. returns to its return address) or not. The way we try to observe this
// is by inspecting the program counter argument, and seeing if it is
// `__anvill_ra` or the (casted) value returned from the `llvm.returnaddress`
// intrinsic.
//
// When we match the expected pattern, we can eliminate calls to
// `__remill_function_return`. If we don't match the pattern, then it suggests
// that it is possible that the function alters its return address, or that
// something is preventing our analysis from deducing that the return address
// reaches the `__remill_function_return` call's program counter argument.
//
// On x86(-64) and AArch64, we can use the `llvm.addressofreturnaddress` to
// update the return address in place when we fail to match the pattern,
// thereby letting us eliminate the call to `__remill_function_return`.
//
// NOTE(pag): This pass should be applied as late as possible, as the call to
//            `__remill_function_return` depends upon the memory pointer.
llvm::FunctionPass *CreateRemoveRemillFunctionReturns(
    const EntityLifter &lifter) {
  return new RemoveRemillFunctionReturns(lifter);
}

}  // namespace anvill
