/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

#include "BaseFunctionPass.h"

#include <doctest.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Verifier.h>

#include <iostream>

#include "RecoverStackFrameInformation.h"
#include "Utils.h"

namespace anvill {

TEST_SUITE("BaseFunctionPass") {
  TEST_CASE("BaseFunctionPass::SelectInstructions") {
    llvm::LLVMContext context;
    auto module = LoadTestData(context, "BaseFunctionPass.ll");
    REQUIRE(module != nullptr);

    auto function = module->getFunction("SelectInstructions");
    REQUIRE(function != nullptr);

    auto instruction_list =
        BaseFunctionPass<std::monostate>::SelectInstructions<llvm::StoreInst>(
            *function);

    CHECK(instruction_list.size() == 1U);

    instruction_list = BaseFunctionPass<std::monostate>::SelectInstructions<
        llvm::StoreInst, llvm::LoadInst>(*function);

    CHECK(instruction_list.size() == 2U);

    instruction_list = BaseFunctionPass<std::monostate>::SelectInstructions<
        llvm::BinaryOperator, llvm::LoadInst>(*function);

    CHECK(instruction_list.size() == 3U);

    instruction_list = BaseFunctionPass<std::monostate>::SelectInstructions<
        llvm::PHINode, llvm::BinaryOperator, llvm::LoadInst>(*function);

    CHECK(instruction_list.size() == 4U);
  }

  TEST_CASE("BaseFunctionPass::InstructionReferencesStackPointer") {
    llvm::LLVMContext context;
    auto module = LoadTestData(context, "BaseFunctionPass.ll");
    REQUIRE(module != nullptr);

    auto function = module->getFunction("InstructionReferencesStackPointer");
    REQUIRE(function != nullptr);

    // Attempt to run the InstructionReferencesStackPointer method on every
    // instruction

    std::size_t reference_count{};

    for (auto &instruction : llvm::instructions(*function)) {
      if (BaseFunctionPass<std::monostate>::InstructionReferencesStackPointer(
              module.get(), instruction)) {
        ++reference_count;
      }
    }

    CHECK(reference_count == 1U);
  }
}

}  // namespace anvill
