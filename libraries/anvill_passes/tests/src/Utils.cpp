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

#include "Utils.h"

#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/SourceMgr.h>

#include <iostream>

namespace anvill {

bool VerifyModule(llvm::Module *module) {
  std::string error_buffer;
  llvm::raw_string_ostream error_stream(error_buffer);

  if (llvm::verifyModule(*module, &error_stream) != 0) {
    auto module_name = module->getName().str();

    std::string error_message =
        "Module verification failed for '" + module_name + "'";

    error_stream.flush();
    if (!error_buffer.empty()) {
      error_message += ": " + error_buffer;
    }

    std::cerr << error_message << std::endl;
    return false;
  }

  return true;
}

std::unique_ptr<llvm::Module> LoadTestData(llvm::LLVMContext &context,
                                           const std::string &data_name) {
  auto data_path = std::string(ANVILL_TEST_DATA_PATH) + "/" + data_name;

  llvm::SMDiagnostic error;
  auto llvm_module = std::unique_ptr<llvm::Module>(
      llvm::parseIRFile(data_path, error, context));

  if (llvm_module == nullptr) {
    throw std::runtime_error(
        "Failed to load the anvill_passes test data named " + data_name + ": " +
        error.getMessage().str());
  }

  std::string error_buffer;
  llvm::raw_string_ostream error_stream(error_buffer);

  auto succeeded = llvm::verifyModule(*llvm_module.get(), &error_stream) == 0;
  error_stream.flush();

  if (!succeeded) {
    std::string error_message =
        "Module verification failed for '" + data_name + "'";

    if (!error_buffer.empty()) {
      error_message += ": " + error_buffer;
    }

    std::cerr << error_message << std::endl;
  }

  return llvm_module;
}

bool RunFunctionPass(
    llvm::Module *module,
    std::function<void(llvm::FunctionPassManager &)> add_function_pass) {
  llvm::PassBuilder pass_builder;
  llvm::FunctionPassManager fpm;
  llvm::FunctionAnalysisManager fam;
  pass_builder.registerFunctionAnalyses(fam);
  add_function_pass(fpm);

  for (auto &function : *module) {
    fpm.run(function, fam);
  }

  return VerifyModule(module);
}

const PlatformList &GetSupportedPlatforms(void) {
  static const PlatformList kSupportedPlatforms = {{"linux", "amd64"}};

  return kSupportedPlatforms;
}

}  // namespace anvill
