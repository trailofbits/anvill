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
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

#include <unordered_set>
#include <utility>
#include <vector>

namespace anvill {
namespace {

class RemoveTrivialPhisAndSelects final
    : public llvm::PassInfoMixin<RemoveTrivialPhisAndSelects> {
 public:
  llvm::PreservedAnalyses run(llvm::Function &func,
                              llvm::FunctionAnalysisManager &fam);
};

llvm::PreservedAnalyses
RemoveTrivialPhisAndSelects::run(llvm::Function &func,
                                 llvm::FunctionAnalysisManager &fam) {

  std::unordered_set<llvm::Instruction *> remove;
  std::vector<llvm::Instruction *> work_list;
  std::vector<llvm::Instruction *> next_work_list;
  std::vector<std::pair<llvm::Use *, llvm::Value *>> replacements;

  auto changed = false;

  {
    for (auto &inst : llvm::instructions(func)) {
      next_work_list.push_back(&inst);
    }
  }

  while (!next_work_list.empty()) {
    next_work_list.swap(work_list);
    next_work_list.clear();

    for (auto inst : work_list) {

      // Check if `inst` is a `phi [BB0, VAL], ..., [BBn, VAL]`, and schedule a
      // replacement of the `phi` with `VAL`.
      if (auto phi = llvm::dyn_cast<llvm::PHINode>(inst)) {
        const auto base_val = phi->getIncomingValue(0);
        for (auto &use : phi->incoming_values()) {
          const auto val = use.get();
          if (val != base_val) {
            goto next;
          }
        }

        for (auto &use : phi->uses()) {
          replacements.emplace_back(&use, base_val);
        }
        remove.insert(phi);

      next:
        continue;

      // Check if `inst` is a `select cond, VAL, VAL`, and schedule a
      // replacement of the `select` with `VAL`.
      } else if (auto sel = llvm::dyn_cast<llvm::SelectInst>(inst)) {
        const auto base_val = sel->getTrueValue();
        if (base_val == sel->getFalseValue()) {
          for (auto &use : sel->uses()) {
            replacements.emplace_back(&use, base_val);
          }
          remove.insert(sel);
        }
      }
    }

    // If one PHI/Select leads to another, then this will possibly help
    // us handle those situations.
    for (auto [use, new_val] : replacements) {
      if (auto user_inst = llvm::dyn_cast<llvm::Instruction>(use->getUser())) {
        next_work_list.push_back(user_inst);
      }
      use->set(new_val);
      changed = true;
    }

    replacements.clear();
  }

  // Remove the no longer needed instructions.
  for (auto inst : remove) {
    if (inst->use_empty()) {
      inst->eraseFromParent();
      changed = true;
    }
  }

  return changed ? llvm::PreservedAnalyses::none()
                 : llvm::PreservedAnalyses::all();
}

}  // namespace

// Removes trivial PHI and select nodes. These are PHI and select nodes whose
// incoming values or true/false values match. This can happen as a result of
// the instruction folding pass that hoists and folds values up through selects
// and PHI nodes, followed by the select sinking pass, which pushes values down.
void AddRemoveTrivialPhisAndSelects(llvm::FunctionPassManager &fpm) {
  fpm.addPass(RemoveTrivialPhisAndSelects());
}

}  // namespace anvill
