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

#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/IR/Verifier.h>

#include <iostream>

#include "Utils.h"

namespace anvill {

TEST_SUITE("SplitStackFrameAtReturnAddress") {
  TEST_CASE("Run the whole pass on a well-formed function") {
    llvm::LLVMContext llvm_context;
    auto module =
        LoadTestData(llvm_context, "SplitStackFrameAtReturnAddress.ll");

    REQUIRE(module != nullptr);

    auto error_manager = ITransformationErrorManager::Create();
    CHECK(RunFunctionPass(
        module.get(), [&error_manager](llvm::FunctionPassManager &fpm) {
          AddSplitStackFrameAtReturnAddress(fpm, *error_manager.get());
        }));

    for (const auto &error : error_manager->ErrorList()) {
      CHECK_MESSAGE(false, error.description);
    }

    REQUIRE(error_manager->ErrorList().empty());
  }
}

}  // namespace anvill
