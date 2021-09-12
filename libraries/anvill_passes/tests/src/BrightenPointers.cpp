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

#include <anvill/Analysis/CrossReferenceResolver.h>
#include <anvill/Lifters/EntityLifter.h>
#include <anvill/Lifters/Options.h>
#include <anvill/Providers/MemoryProvider.h>
#include <anvill/Providers/TypeProvider.h>
#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Lifter.h>
#include <remill/OS/OS.h>

#include <iostream>

#include "Utils.h"

namespace anvill {

void printFunc(const llvm::Module &mod, const std::string &name,
               const std::string &msg) {
  for (auto &f : mod) {
    if (f.hasName() && f.getName() == name) {
      std::cout << msg << std::endl;
      f.print(llvm::errs(), nullptr);
    }
  }
}
bool checkMod(const llvm::Module &mod) {

  // Verify the module
  std::string error_buffer;
  llvm::raw_string_ostream error_stream(error_buffer);

  auto succeeded = llvm::verifyModule(mod, &error_stream) == 0;
  error_stream.flush();

  CHECK(succeeded);
  if (!succeeded) {
    std::string error_message = "Module verification failed";
    if (!error_buffer.empty()) {
      error_message += ": " + error_buffer;
    }

    std::cerr << error_message << std::endl;
  }
  return succeeded;
}
/*
class BrightenPointersFixture {
 public:
  BrightenPointersFixture(void)
      : arch(remill::Arch::Build(&llvm_context, remill::kOSLinux,
                                 remill::kArchAMD64)),
        mem(MemoryProvider::CreateNullMemoryProvider()),
        types(TypeProvider::CreateNullTypeProvider(llvm_context)) {}

  llvm::LLVMContext llvm_context;
  const remill::Arch::ArchPtr arch;
  const std::shared_ptr<MemoryProvider> mem;
  const std::shared_ptr<TypeProvider> types;
};
*/
bool RunFunctionPass(
    llvm::Module &module,
    std::function<void(llvm::FunctionPassManager &fpm)> add_function_pass) {
  llvm::PassBuilder pass_builder;
  llvm::FunctionPassManager fpm;
  llvm::FunctionAnalysisManager fam;
  pass_builder.registerFunctionAnalyses(fam);
  add_function_pass(fpm);

  for (auto &function : module) {
    fpm.run(function, fam);
  }

  return VerifyModule(&module);
}

TEST_SUITE("BrightenPointers") {

  TEST_CASE("Run the whole pass on a well-formed function") {

    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "gep_add.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }

  TEST_CASE("multiple_bitcast") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "multiple_bitcast.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }

  TEST_CASE("don't crash on loops") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "loop_test.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }

  TEST_CASE("challenge 1") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "rx_message.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));

    // mod->print(llvm::errs(), nullptr);

    CHECK(checkMod(*mod));
  }


  TEST_CASE("challenge 2") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "chall2.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));

    // mod->print(llvm::errs(), nullptr);

    CHECK(checkMod(*mod));
  }

  TEST_CASE("ret0") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "ret0.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("jmp0") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "jmp0.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_array_swap") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_array_swap_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_binja_var_none_type") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_binja_var_none_type_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    mod->print(llvm::errs(), nullptr);
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_bitops") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_bitops_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_binops") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_binops_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_cast") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_cast_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_init_list_rt.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_init_list_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_inttoptr_rt.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_inttoptr_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_nullptr_rt.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_nullptr_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_ret0_rt.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_ret0_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_struct_rt.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_struct_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_struct_swap_rt.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_struct_swap_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_trunc_rt.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_trunc_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_zeroinit.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_zeroinit_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_zext_rt.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_zext_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_rx.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_rx.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod, [](llvm::FunctionPassManager &fpm) {
      AddBrightenPointerOperations(fpm, 250U);
    }));
    CHECK(checkMod(*mod));
  }
}

};  // namespace anvill
