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

class RemoveDelaySlotIntrinsics final
    : public llvm::PassInfoMixin<RemoveDelaySlotIntrinsics> {
 public:
  llvm::PreservedAnalyses run(llvm::Function &func,
                              llvm::FunctionAnalysisManager &fam);
};

// Try to lower remill memory access intrinsics.
llvm::PreservedAnalyses
RemoveDelaySlotIntrinsics::run(llvm::Function &func,
                               llvm::FunctionAnalysisManager &fam) {
  auto module = func.getParent();
  auto begin = module->getFunction("__remill_delay_slot_begin");
  auto end = module->getFunction("__remill_delay_slot_end");

  if (!begin && !end) {
    return llvm::PreservedAnalyses::all();
  }

  auto calls = FindFunctionCalls(func, [=](llvm::CallBase *call) -> bool {
    const auto func = call->getCalledFunction();
    return func == begin || func == end;
  });

  for (llvm::CallBase *call : calls) {
    auto mem_ptr = call->getArgOperand(0);
    CopyMetadataTo(call, mem_ptr);
    call->replaceAllUsesWith(mem_ptr);
    call->eraseFromParent();
  }

  return !calls.empty() ? llvm::PreservedAnalyses::none()
                        : llvm::PreservedAnalyses::all();
}

}  // namespace

// Removes calls to `__remill_delay_slot_begin` and `__remill_delay_slot_end`.
void AddRemoveDelaySlotIntrinsics(llvm::FunctionPassManager &fpm) {
  fpm.addPass(RemoveDelaySlotIntrinsics());
}

}  // namespace anvill
