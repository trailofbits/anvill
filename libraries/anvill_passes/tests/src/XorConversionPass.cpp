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

#include <anvill/Lifters/EntityLifter.h>
#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#include <iostream>

#include "Utils.h"

namespace anvill {

TEST_SUITE("XorConversion") {
  TEST_CASE("Convert a Xor used in a BranchInst and SelectInst") {
    llvm::LLVMContext llvm_context;
    auto module = LoadTestData(llvm_context, "xor_conversion.ll");

    auto arch = remill::Arch::Build(&llvm_context, remill::GetOSName("linux"),
                                    remill::GetArchName("amd64"));
    REQUIRE(arch != nullptr);

    anvill::LifterOptions options(arch.get(), *module.get(), nullptr);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options, nullptr, nullptr);

    CHECK(RunFunctionPass(module.get(), [](llvm::FunctionPassManager &fpm) {
      AddConvertXorToCmp(fpm);
    }));

    const auto xor_as_not = module->getFunction("xor_as_not");
    int xor_count = 0;
    for (auto &inst : llvm::instructions(xor_as_not)) {
      if (auto binop = llvm::dyn_cast<llvm::BinaryOperator>(&inst)) {

        // binary op is a xor
        if (binop->getOpcode() == llvm::Instruction::Xor) {
          xor_count += 1;
        }
      }
    }

    REQUIRE(xor_as_not);
    REQUIRE(xor_count == 0);
  }

  TEST_CASE("DO NOT convert a xor used as a branch/select") {
    llvm::LLVMContext llvm_context;
    auto module = LoadTestData(llvm_context, "xor_conversion_nochange.ll");

    auto arch = remill::Arch::Build(&llvm_context, remill::GetOSName("linux"),
                                    remill::GetArchName("amd64"));
    REQUIRE(arch != nullptr);

    anvill::LifterOptions options(arch.get(), *module.get(), nullptr);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options, nullptr, nullptr);

    CHECK(RunFunctionPass(module.get(), [](llvm::FunctionPassManager &fpm) {
      AddConvertXorToCmp(fpm);
    }));

    const auto xor_as_not_nochange = module->getFunction("xor_as_not_nochange");
    int xor_count = 0;
    for (auto &inst : llvm::instructions(xor_as_not_nochange)) {
      if (auto binop = llvm::dyn_cast<llvm::BinaryOperator>(&inst)) {

        // binary op is a xor
        if (binop->getOpcode() == llvm::Instruction::Xor) {
          xor_count += 1;
        }
      }
    }

    REQUIRE(xor_as_not_nochange);
    REQUIRE(xor_count == 1);
  }
}


}  // namespace anvill
