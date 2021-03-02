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

#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>

namespace anvill {

std::unique_ptr<llvm::Module> LoadTestData(llvm::LLVMContext &context,
                                           const std::string &data_name);

std::unique_ptr<llvm::Module>
RunFunctionPass(llvm::LLVMContext &context, const std::string &test_data_name,
                llvm::FunctionPass *function_pass);

}  // namespace anvill
