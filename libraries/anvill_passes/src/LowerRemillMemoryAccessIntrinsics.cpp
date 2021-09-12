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

#include <anvill/Transforms.h>
#include <glog/logging.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

#include "Utils.h"

namespace anvill {
namespace {

class LowerRemillMemoryAccessIntrinsics final
    : public llvm::PassInfoMixin<LowerRemillMemoryAccessIntrinsics> {
 public:
  llvm::PreservedAnalyses run(llvm::Function &func,
                              llvm::FunctionAnalysisManager &fam);
};

// Lower a memory read intrinsic into a `load` instruction.
static void ReplaceMemReadOp(llvm::CallBase *call_inst, llvm::Type *val_type) {
  auto addr = call_inst->getArgOperand(1);
  llvm::IRBuilder<> ir(call_inst);
  auto ptr = ir.CreateIntToPtr(addr, llvm::PointerType::get(val_type, 0));
  CopyMetadataTo(call_inst, ptr);
  llvm::Value *val = ir.CreateLoad(ptr);
  CopyMetadataTo(call_inst, val);
  if (val_type->isX86_FP80Ty() || val_type->isFP128Ty()) {
    val = ir.CreateFPTrunc(val, call_inst->getType());
    CopyMetadataTo(call_inst, val);
  }
  call_inst->replaceAllUsesWith(val);
  call_inst->eraseFromParent();
}

// Lower a memory write intrinsic into a `store` instruction.
static void ReplaceMemWriteOp(llvm::CallBase *call_inst, llvm::Type *val_type) {
  auto mem_ptr = call_inst->getArgOperand(0);
  auto addr = call_inst->getArgOperand(1);
  auto val = call_inst->getArgOperand(2);

  llvm::IRBuilder<> ir(call_inst);
  auto ptr = ir.CreateIntToPtr(addr, llvm::PointerType::get(val_type, 0));
  CopyMetadataTo(call_inst, ptr);
  if (val_type->isX86_FP80Ty() || val_type->isFP128Ty()) {
    val = ir.CreateFPExt(val, val_type);
    CopyMetadataTo(call_inst, val);
  }

  val = ir.CreateStore(val, ptr);
  CopyMetadataTo(call_inst, val);
  call_inst->replaceAllUsesWith(mem_ptr);
  call_inst->eraseFromParent();
}

// Dispatch to the proper memory replacement function given a function call.
static bool ReplaceMemoryOp(llvm::CallBase *call) {
  const auto func = call->getCalledFunction();
  const auto func_name = func->getName();

  // Perform a value type adjustment. Remill re-interprets loads/stores of
  // extended precision and quad precision floating point values as operating
  // on double precision floats, then opaquely performing the necessary
  // conversions at the memory boundary.
  auto adjust_val_type = [=](llvm::Type *val_type) -> llvm::Type * {
    auto &context = val_type->getContext();
    if (func_name.endswith("f80")) {
      return llvm::Type::getX86_FP80Ty(context);
    } else if (func_name.endswith("f128")) {
      return llvm::Type::getFP128Ty(context);
    } else {
      return val_type;
    }
  };

  // `val = __remill_read_memory_NN(mem, addr)`.
  if (func_name.startswith("__remill_read_memory_")) {
    const auto val_type = adjust_val_type(call->getType());
    ReplaceMemReadOp(call, val_type);
    return true;

  // `mem = __remill_write_memory_NN(mem, addr, val)`.
  } else if (func_name.startswith("__remill_write_memory_")) {
    const auto val_type = adjust_val_type(call->getArgOperand(2)->getType());
    ReplaceMemWriteOp(call, val_type);
    return true;

  } else {
    LOG(ERROR) << "Missing support for lowering memory operation "
               << func_name.str();
    return false;
  }
}

// Try to lower remill memory access intrinsics.
llvm::PreservedAnalyses
LowerRemillMemoryAccessIntrinsics::run(llvm::Function &func,
                                       llvm::FunctionAnalysisManager &fam) {
  auto calls = FindFunctionCalls(func, [](llvm::CallBase *call) -> bool {
    const auto func = call->getCalledFunction();
    if (!func) {
      return false;
    }

    // TODO(pag): Add support for atomic read-modify-write intrinsics.
    const auto name = func->getName();
    return name.startswith("__remill_read_memory_") ||
           name.startswith("__remill_write_memory_");
  });

  auto ret = false;
  for (auto call : calls) {
    ret = ReplaceMemoryOp(call) || ret;
  }

  return ret ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
}

}  // namespace

// Lowers the `__remill_read_memory_NN`, `__remill_write_memory_NN`, and the
// various atomic read-modify-write variants into LLVM loads and stores.
void AddLowerRemillMemoryAccessIntrinsics(llvm::FunctionPassManager &fpm) {
  fpm.addPass(LowerRemillMemoryAccessIntrinsics());
}

}  // namespace anvill
