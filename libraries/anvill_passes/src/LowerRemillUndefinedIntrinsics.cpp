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
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>

#include <vector>

namespace anvill {
namespace {

class LowerRemillUndefinedIntrinsics final
    : public llvm::PassInfoMixin<LowerRemillUndefinedIntrinsics> {
 public:
  llvm::PreservedAnalyses run(llvm::Function &func,
                              llvm::FunctionAnalysisManager &fam);
};

llvm::PreservedAnalyses
LowerRemillUndefinedIntrinsics::run(llvm::Function &func,
                                    llvm::FunctionAnalysisManager &fam) {
  std::vector<llvm::CallInst *> calls;

  for (auto &inst : llvm::instructions(func)) {
    if (auto call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
      if (auto callee = call->getCalledFunction();
          callee && callee->getName().startswith("__remill_undefined_")) {
        calls.push_back(call);
      }
    }
  }

  auto changed = false;
  for (auto call : calls) {
    auto *undef_val = llvm::UndefValue::get(call->getType());
    CopyMetadataTo(call, undef_val);
    call->replaceAllUsesWith(undef_val);
    call->eraseFromParent();
    changed = true;
  }

  return changed ? llvm::PreservedAnalyses::none()
                 : llvm::PreservedAnalyses::all();
}

}  // namespace

// Some machine code instructions explicitly introduce undefined values /
// behavior. Often, this is a result of the CPUs of different steppings of
// an ISA producing different results for specific registers. For example,
// some instructions leave the value of specific arithmetic flags instructions
// in an undefined state.
//
// Remill models these situations using opaque function calls, i.e. an
// undefined value is produced via a call to something like
// `__remill_undefined_8`, which represents an 8-bit undefined value. We want
// to lower these to `undef` values in LLVM; however, we don't want to do this
// too early, otherwise the "undefinedness" can spread and possibly get out
// of control.
//
// This pass exists to do the lowering to `undef` values, and should be run
// as late as possible.
void AddLowerRemillUndefinedIntrinsics(llvm::FunctionPassManager &fpm) {
  fpm.addPass(LowerRemillUndefinedIntrinsics());
}

}  // namespace anvill
