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

class RemoveDelaySlotIntrinsics final : public llvm::FunctionPass {
 public:
  RemoveDelaySlotIntrinsics(void) : llvm::FunctionPass(ID) {}

  bool runOnFunction(llvm::Function &func) final;

 private:
  static char ID;
};

char RemoveDelaySlotIntrinsics::ID = '\0';

// Try to lower remill memory access intrinsics.
bool RemoveDelaySlotIntrinsics::runOnFunction(llvm::Function &func) {
  auto module = func.getParent();
  auto begin = module->getFunction("__remill_delay_slot_begin");
  auto end = module->getFunction("__remill_delay_slot_end");

  if (!begin && !end) {
    return false;
  }

  auto calls = FindFunctionCalls(func, [=](llvm::CallBase *call) -> bool {
    const auto func = call->getCalledFunction();
    return func == begin || func == end;
  });

  for (llvm::CallBase *call : calls) {
    auto mem_ptr = call->getArgOperand(0);
    call->replaceAllUsesWith(mem_ptr);
    call->eraseFromParent();
  }

  return !calls.empty();
}

}  // namespace

// Removes calls to `__remill_delay_slot_begin` and `__remill_delay_slot_end`.
llvm::FunctionPass *CreateRemoveDelaySlotIntrinsics(void) {
  return new RemoveDelaySlotIntrinsics;
}

}  // namespace anvill
