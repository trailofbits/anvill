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

#pragma once

#include "BaseFunctionPass.h"

#include <llvm/IR/Dominators.h>

namespace anvill {

class InstructionFolderPass final
    : public BaseFunctionPass<InstructionFolderPass> {
 public:
  explicit InstructionFolderPass(ITransformationErrorManager &error_manager);
  InstructionFolderPass(InstructionFolderPass &&) = default;

  virtual ~InstructionFolderPass(void) override = default;

  // Creates a new InstructionFolderPass object
  static void Add(llvm::FunctionPassManager &fpm,
                  ITransformationErrorManager &error_manager);

  // Function pass entry point
  llvm::PreservedAnalyses Run(llvm::Function &function);

  // Folds `Select` instructions interacting with `CastInst`,
  // `BinaryOperator` and `GetElementPtrInst` instructions
  //
  // Returns true if the function was changed
  bool FoldSelectInstruction(InstructionList &output,
                             llvm::Instruction *instr);

  // A single incoming value + basic_block for a PHI node
  struct IncomingValue final {
    llvm::BasicBlock *basic_block{nullptr};
    llvm::Value *value{nullptr};
  };

  // A list of incoming values for a PHI node
  using IncomingValueList = std::vector<IncomingValue>;

  // This structure describes an instruction replacement
  struct InstructionReplacement final {
    llvm::Instruction *original_instr{nullptr};
    llvm::Instruction *replacement_instr{nullptr};
  };

  // A list of instruction replacements to perform at the end of
  // a folding procedure
  using InstructionReplacementList = std::vector<InstructionReplacement>;

  // Performs instruction replacements according to the given list, removing the
  // dropping all the instructions that are no longer needed
  static void PerformInstructionReplacements(
      const InstructionReplacementList &replacement_list);

  // Folds `PHINode` instructions interacting with `CastInst`,
  // `BinaryOperator` and `GetElementPtrInst` instructions
  //
  // Returns true if the function was changed
  bool FoldPHINode(InstructionList &output, llvm::Instruction *instr);

  // Before we can fold a `GetElementPtrInst` instruction, we have to
  // collect the indices. This function will do the work, and return
  // false if any of them makes the folding not possible
  static bool
  CollectAndValidateGEPIndexes(std::vector<llvm::Value *> &index_list,
                               llvm::Instruction *phi_or_select_instr,
                               llvm::Instruction *gep_instr);

  // Folders for
  //   `SelectInst` + `BinaryOperator`
  //   `PHINode` + `BinaryOperator`
  //
  //   src:
  //     x = select cond, true_value, false_value ; (or PHI)
  //     y = add z, x
  //
  //   dst
  //     y = select cond, (add z, true_value), (add z, false_value) ; (or PHI)
  //
  static bool FoldSelectWithBinaryOp(llvm::Instruction *&output,
                                     llvm::Instruction *select_instr,
                                     llvm::Value *condition,
                                     llvm::Value *true_value,
                                     llvm::Value *false_value,
                                     llvm::Instruction *binary_op_instr);

  bool FoldPHINodeWithBinaryOp(llvm::Instruction *&output,
                                      llvm::Instruction *phi_node,
                                      IncomingValueList &incoming_values,
                                      llvm::Instruction *binary_op_instr);

  // Folders for
  //   `SelectInst` + `CastInst`
  //   `PHINode` + `CastInst`
  //
  //   src:
  //     x = select cond, true_value, false_value ; (or PHI)
  //     y = inttoptr x
  //
  //   dst
  //     new_true_value = inttoptr true_value
  //     new_false_value = inttoptr false_value
  //     y = select cond, new_true_value, new_false_value ; (or PHI)
  //
  static bool FoldSelectWithCastInst(llvm::Instruction *&output,
                                     llvm::Instruction *select_instr,
                                     llvm::Value *condition,
                                     llvm::Value *true_value,
                                     llvm::Value *false_value,
                                     llvm::Instruction *cast_instr);

  bool FoldPHINodeWithCastInst(llvm::Instruction *&output,
                               llvm::Instruction *phi_node,
                               IncomingValueList &incoming_values,
                               llvm::Instruction *cast_instr);

  // Folders for
  //   `SelectInst` + `GetElementPtrInst`
  //   `PHINode` + `GetElementPtrInst`
  //
  //   src:
  //     x = select cond, true_value, false_value ; (or PHI)
  //     y = getelementptr x [indexes]
  //
  //   dst
  //     new_true_value = getelementptr true_value [indexes]
  //     new_false_value = getelementptr false_value [indexes]
  //     y = select cond, new_true_value, new_false_value ; (or PHI)
  //
  static bool
  FoldSelectWithGEPInst(llvm::Instruction *&output,
                        llvm::Instruction *select_instr, llvm::Value *condition,
                        llvm::Value *true_value, llvm::Value *false_value,
                        llvm::Instruction *gep_instr);

  bool FoldPHINodeWithGEPInst(llvm::Instruction *&output,
                                     llvm::Instruction *phi_node,
                                     IncomingValueList &incoming_values,
                                     llvm::Instruction *cast_instr);

  std::unique_ptr<llvm::DominatorTree> dt;
};

}  // namespace anvill
