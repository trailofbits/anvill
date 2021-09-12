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
#include <llvm/IR/Function.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

namespace anvill {
namespace {

class RemoveCompilerBarriers final
    : public llvm::PassInfoMixin<RemoveCompilerBarriers> {
 public:
  llvm::PreservedAnalyses run(llvm::Function &func,
                              llvm::FunctionAnalysisManager &fam);
};

// Try to lower remill memory access intrinsics.
llvm::PreservedAnalyses
RemoveCompilerBarriers::run(llvm::Function &func,
                            llvm::FunctionAnalysisManager &fam) {
  std::vector<llvm::CallBase *> to_remove;

  for (llvm::BasicBlock &block : func) {
    auto prev_is_compiler_barrier = false;
    llvm::CallBase *prev_barrier = nullptr;
    for (auto &inst : block) {
      if (auto call = llvm::dyn_cast<llvm::CallBase>(&inst)) {
        const auto called_val = call->getCalledOperand();
        const auto inline_asm = llvm::dyn_cast<llvm::InlineAsm>(called_val);
        if (inline_asm) {
          if (inline_asm->hasSideEffects() && call->getType()->isVoidTy() &&
              inline_asm->getAsmString().empty()) {

            if (prev_is_compiler_barrier) {
              to_remove.push_back(call);
            } else {
              prev_barrier = call;
            }
            prev_is_compiler_barrier = true;

          } else {
            prev_is_compiler_barrier = false;
            prev_barrier = nullptr;
          }

        } else if (auto target_func = call->getCalledFunction()) {
          if (target_func->hasExternalLinkage()) {
            if (prev_is_compiler_barrier && prev_barrier) {
              to_remove.push_back(prev_barrier);
            }
            prev_is_compiler_barrier = true;
          } else {
            prev_is_compiler_barrier = false;
          }

          prev_barrier = nullptr;

        } else {
          prev_is_compiler_barrier = false;
          prev_barrier = nullptr;
        }
      } else {
        prev_is_compiler_barrier = false;
        prev_barrier = nullptr;
      }
    }
  }

  for (auto call_inst : to_remove) {
    call_inst->eraseFromParent();
  }

  return !to_remove.empty() ? llvm::PreservedAnalyses::none()
                            : llvm::PreservedAnalyses::all();
}

}  // namespace

// Remill semantics sometimes contain compiler barriers (empty inline assembly
// statements), especially related to floating point code (i.e. preventing
// re-ordering of floating point operations so that we can capture the flags).
// This pass eliminates those empty inline assembly statements.
void AddRemoveCompilerBarriers(llvm::FunctionPassManager &fpm) {
  fpm.addPass(RemoveCompilerBarriers());
}

}  // namespace anvill
