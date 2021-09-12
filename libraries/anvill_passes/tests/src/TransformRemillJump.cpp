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

#include <anvill/Lifters/EntityLifter.h>
#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/IR/Verifier.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#include <iostream>

#include "Utils.h"

namespace anvill {

TEST_SUITE("TransformRemillJump_Test0") {
  TEST_CASE("Run the pass on function having _remill_jump as tail call") {
    llvm::LLVMContext llvm_context;
    auto module = LoadTestData(llvm_context, "TransformRemillJumpData0.ll");

    auto arch = remill::Arch::Build(&llvm_context, remill::GetOSName("linux"),
                                    remill::GetArchName("amd64"));
    REQUIRE(arch != nullptr);

    anvill::LifterOptions options(arch.get(), *module.get(), nullptr);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options, nullptr, nullptr);

    CHECK(RunFunctionPass(module.get(),
                          [&lifter](llvm::FunctionPassManager &fpm) {
                            AddTransformRemillJumpIntrinsics(fpm, lifter);
                          }));

    const auto ret_func = module->getFunction("__remill_function_return");
    const auto jmp_func = module->getFunction("__remill_jump");

    REQUIRE((ret_func && !ret_func->use_empty()));
    REQUIRE((!jmp_func || jmp_func->use_empty()));
  }
}

TEST_SUITE("TransformRemillJump_Test1") {
  TEST_CASE("Run the pass on function having _remill_jump as tail call") {
    llvm::LLVMContext llvm_context;
    auto module = LoadTestData(llvm_context, "TransformRemillJumpData1.ll");

    auto arch = remill::Arch::Build(&llvm_context, remill::GetOSName("linux"),
                                    remill::GetArchName("amd64"));
    REQUIRE(arch != nullptr);

    anvill::LifterOptions options(arch.get(), *module.get(), nullptr);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options, nullptr, nullptr);

    CHECK(RunFunctionPass(module.get(),
                          [&lifter](llvm::FunctionPassManager &fpm) {
                            AddTransformRemillJumpIntrinsics(fpm, lifter);
                          }));

    const auto ret_func = module->getFunction("__remill_function_return");
    const auto jmp_func = module->getFunction("__remill_jump");


    REQUIRE((ret_func && !ret_func->use_empty()));
    REQUIRE((!jmp_func || jmp_func->use_empty()));
  }
}

TEST_SUITE("TransformRemillJump_ARM32_0") {
  TEST_CASE("Run the pass on function having _remill_jump as tail call") {
    llvm::LLVMContext llvm_context;
    auto module =
        LoadTestData(llvm_context, "TransformRemillJumpDataARM32_0.ll");

    auto arch = remill::Arch::Build(&llvm_context, remill::GetOSName("linux"),
                                    remill::GetArchName("aarch32"));
    REQUIRE(arch != nullptr);

    anvill::LifterOptions options(arch.get(), *module.get(), nullptr);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options, nullptr, nullptr);

    CHECK(RunFunctionPass(module.get(),
                          [&lifter](llvm::FunctionPassManager &fpm) {
                            AddTransformRemillJumpIntrinsics(fpm, lifter);
                          }));

    const auto ret_func = module->getFunction("__remill_function_return");
    const auto jmp_func = module->getFunction("__remill_jump");


    REQUIRE((ret_func && !ret_func->use_empty()));
    REQUIRE((!jmp_func || jmp_func->use_empty()));
  }
}

TEST_SUITE("TransformRemillJump_ARM32_1") {
  TEST_CASE("Run the pass on function having _remill_jump as tail call") {
    llvm::LLVMContext llvm_context;
    auto module =
        LoadTestData(llvm_context, "TransformRemillJumpDataARM32_1.ll");

    auto arch = remill::Arch::Build(&llvm_context, remill::GetOSName("linux"),
                                    remill::GetArchName("aarch32"));
    REQUIRE(arch != nullptr);

    anvill::LifterOptions options(arch.get(), *module.get(), nullptr);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options, nullptr, nullptr);

    CHECK(RunFunctionPass(module.get(),
                          [&lifter](llvm::FunctionPassManager &fpm) {
                            AddTransformRemillJumpIntrinsics(fpm, lifter);
                          }));

    const auto ret_func = module->getFunction("__remill_function_return");
    const auto jmp_func = module->getFunction("__remill_jump");


    REQUIRE((ret_func && !ret_func->use_empty()));
    REQUIRE((!jmp_func || jmp_func->use_empty()));
  }
}

}  // namespace anvill
