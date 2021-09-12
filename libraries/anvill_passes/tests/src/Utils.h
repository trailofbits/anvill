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

#pragma once

#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>

namespace anvill {

bool VerifyModule(llvm::Module *module);

std::unique_ptr<llvm::Module> LoadTestData(llvm::LLVMContext &context,
                                           const std::string &data_name);

bool RunFunctionPass(
    llvm::Module *module,
    std::function<void(llvm::FunctionPassManager &)> function_pass);

struct Platform final {
  std::string os;
  std::string arch;
};

using PlatformList = std::vector<Platform>;
const PlatformList &GetSupportedPlatforms(void);

}  // namespace anvill
