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

#include "Utils.h"

#include <anvill/ABI.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>

#include <vector>

namespace anvill {
namespace {

class LowerTypeHintIntrinsics final
    : public llvm::PassInfoMixin<LowerTypeHintIntrinsics> {
 public:
  llvm::PreservedAnalyses run(llvm::Function &func,
                              llvm::FunctionAnalysisManager &fam);
};

llvm::PreservedAnalyses
LowerTypeHintIntrinsics::run(llvm::Function &func,
                             llvm::FunctionAnalysisManager &fam) {
  std::vector<llvm::CallInst *> calls;

  for (auto &inst : llvm::instructions(func)) {
    if (auto call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
      if (auto callee = call->getCalledFunction();
          callee && callee->getName().startswith(kTypeHintFunctionPrefix)) {
        calls.push_back(call);
      }
    }
  }

  auto changed = false;
  for (auto call : calls) {
    auto val = call->getArgOperand(0)->stripPointerCasts();
    llvm::IRBuilder<> ir(call);
    auto *cast_val = ir.CreateBitOrPointerCast(val, call->getType());
    CopyMetadataTo(call, cast_val);
    call->replaceAllUsesWith(cast_val);
    changed = true;
  }

  for (auto call : calls) {
    if (call->use_empty()) {
      call->eraseFromParent();
      changed = true;
    }
  }

  return changed ? llvm::PreservedAnalyses::none()
                 : llvm::PreservedAnalyses::all();
}

}  // namespace

// Type information from prior lifting efforts, or from front-end tools
// (e.g. Binary Ninja) is plumbed through the system by way of calls to
// intrinsic functions such as `__anvill_type<blah>`. These function calls
// don't interfere (too much) with optimizations, and they also survive
// optimizations. In general, the key role that they serve is to enable us to
// propagate through pointer type information at an instruction/register
// granularity.
//
// These function calls need to be removed/lowered into `inttoptr` or `bitcast`
// instructions.
void AddLowerTypeHintIntrinsics(llvm::FunctionPassManager &fpm) {
  fpm.addPass(LowerTypeHintIntrinsics());
}

}  // namespace anvill
