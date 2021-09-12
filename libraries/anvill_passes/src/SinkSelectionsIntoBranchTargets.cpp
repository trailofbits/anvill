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


#include "SinkSelectionsIntoBranchTargets.h"

#include <anvill/Transforms.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

#include <magic_enum.hpp>
#include <unordered_set>
#include <utility>
#include <vector>

#include "Utils.h"


namespace anvill {

namespace {

using BranchList = std::vector<llvm::BranchInst *>;

using SelectListMap = std::unordered_map<llvm::SelectInst *, BranchList>;

}  // namespace

void SinkSelectionsIntoBranchTargets::Add(
    llvm::FunctionPassManager &fpm,
    ITransformationErrorManager &error_manager) {
  fpm.addPass(SinkSelectionsIntoBranchTargets(error_manager));
}

SinkSelectionsIntoBranchTargets::FunctionAnalysis
SinkSelectionsIntoBranchTargets::AnalyzeFunction(llvm::Function &function) {

  // Collect all the applicable instructions
  SelectListMap select_list_map;

  for (auto &instruction : llvm::instructions(function)) {

    // Look for `SelectInst` instructions
    auto select_inst = llvm::dyn_cast<llvm::SelectInst>(&instruction);
    if (select_inst == nullptr) {
      continue;
    }

    const auto select_condition = select_inst->getCondition();

    for (auto &use : select_condition->uses()) {

      // Look for users that are conditional branches
      const auto branch_inst = llvm::dyn_cast<llvm::BranchInst>(use.getUser());
      if (branch_inst == nullptr) {
        continue;
      }

      if (!branch_inst->isConditional()) {
        continue;
      }

      // The `SelectInst` and `BranchInst` must share the same
      // condition
      if (branch_inst->getCondition() != select_condition) {
        continue;
      }

      auto select_list_it = select_list_map.find(select_inst);
      if (select_list_it == select_list_map.end()) {
        auto insert_status = select_list_map.insert({select_inst, {}});
        select_list_it = insert_status.first;
      }

      auto &branch_list = select_list_it->second;
      branch_list.emplace_back(branch_inst);
    }
  }

  // Determine which replacements need to happen
  FunctionAnalysis output;

  llvm::DominatorTree doms(function);

  for (auto &select_list_map_p : select_list_map) {
    auto select_inst = select_list_map_p.first;
    auto &branch_list = select_list_map_p.second;

    for (auto branch : branch_list) {
      llvm::BasicBlockEdge taken_edge(branch->getParent(),
                                      branch->getSuccessor(0));

      llvm::BasicBlockEdge not_taken_edge(branch->getParent(),
                                          branch->getSuccessor(1));

      const auto true_val = select_inst->getTrueValue();
      const auto false_val = select_inst->getFalseValue();

      for (auto &select_inst_use : select_inst->uses()) {
        FunctionAnalysis::Replacement replacement;
        replacement.use_to_replace = &select_inst_use;

        if (doms.dominates(taken_edge, select_inst_use)) {
          replacement.replace_with = true_val;

        } else if (doms.dominates(not_taken_edge, select_inst_use)) {
          replacement.replace_with = false_val;
        }

        if (replacement.replace_with == nullptr) {
          continue;
        }

        output.disposable_instruction_list.insert(select_inst);
        output.replacement_list.push_back(std::move(replacement));
      }
    }
  }

  return output;
}

void SinkSelectionsIntoBranchTargets::SinkSelectInstructions(
    const FunctionAnalysis &analysis) {

  for (const auto &replacement : analysis.replacement_list) {
    CopyMetadataTo(replacement.use_to_replace->get(), replacement.replace_with);
    replacement.use_to_replace->set(replacement.replace_with);
  }

  for (auto select_inst : analysis.disposable_instruction_list) {
    if (!select_inst->use_empty()) {
      continue;
    }

    select_inst->eraseFromParent();
  }
}

llvm::PreservedAnalyses
SinkSelectionsIntoBranchTargets::Run(llvm::Function &function) {
  if (function.isDeclaration()) {
    return llvm::PreservedAnalyses::all();
  }

  auto function_analysis = AnalyzeFunction(function);
  if (function_analysis.replacement_list.empty()) {
    return llvm::PreservedAnalyses::all();
  }

  SinkSelectInstructions(function_analysis);
  return llvm::PreservedAnalyses::none();
}

SinkSelectionsIntoBranchTargets::SinkSelectionsIntoBranchTargets(
    ITransformationErrorManager &error_manager)
    : BaseFunctionPass(error_manager) {}

void AddSinkSelectionsIntoBranchTargets(
    llvm::FunctionPassManager &fpm,
    ITransformationErrorManager &error_manager) {
  SinkSelectionsIntoBranchTargets::Add(fpm, error_manager);
}

}  // namespace anvill
