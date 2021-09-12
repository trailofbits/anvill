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

//
// When lifting conditional control-flow, we end up with the following pattern:
//
//        %25 = icmp eq i8 %24, 0
//        %26 = select i1 %25, i64 TAKEN_PC, i64 NOT_TAKEN_PC
//        br i1 %25, label %27, label %34
//
//        27:
//        ... use of %26
//
//        34:
//        ... use of %26
//
// This function pass transforms the above pattern into the following:
//
//        %25 = icmp eq i8 %24, 0
//        br i1 %25, label %27, label %34
//
//        27:
//        ... use of TAKEN_PC
//
//        34:
//        ... use of NOT_TAKEN_PC
//
// When this happens, we're better able to fold cross-references at the targets
// of conditional branches.
//

#pragma once

#include <unordered_map>

#include "BaseFunctionPass.h"

namespace anvill {

class SinkSelectionsIntoBranchTargets final
    : public BaseFunctionPass<SinkSelectionsIntoBranchTargets> {

 public:
  struct FunctionAnalysis final {
    struct Replacement final {
      llvm::Use *use_to_replace{nullptr};
      llvm::Value *replace_with{nullptr};
    };

    using ReplacementList = std::vector<Replacement>;
    using DisposableInstructionList = std::unordered_set<llvm::SelectInst *>;

    ReplacementList replacement_list;
    DisposableInstructionList disposable_instruction_list;
  };

  // Identifies all `select` instructions in `function`, where the `SelectInst`
  // shares the same condition as a conditional branch.
  static FunctionAnalysis AnalyzeFunction(llvm::Function &function);

  // Applies the transformation that moves the `SelectInst` instructions
  // inside each branch
  static void SinkSelectInstructions(const FunctionAnalysis &analysis);

  // Creates a new SinkSelectionsIntoBranchTargets object
  static void Add(llvm::FunctionPassManager &fpm,
                  ITransformationErrorManager &error_manager);

  // Function pass entry point
  llvm::PreservedAnalyses Run(llvm::Function &function);

  virtual ~SinkSelectionsIntoBranchTargets(void) override = default;

 private:
  SinkSelectionsIntoBranchTargets(ITransformationErrorManager &error_manager);
};

}  // namespace anvill
