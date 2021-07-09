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

#include "anvill/Optimize.h"

#include <glog/logging.h>

// clang-format off
#include <remill/BC/Compat/CTypes.h>
#include <remill/BC/Compat/ScalarTransforms.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/Utils/Local.h>

// clang-format on

#include <anvill/Transforms.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Compat/ScalarTransforms.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>

#include <unordered_set>
#include <vector>

#include "anvill/ABI.h"
#include "anvill/Decl.h"
#include "anvill/Program.h"
#include "anvill/Util.h"

DEFINE_uint32(
    pointer_brighten_gas, 64u,
    "Amount of internal iterations permitted for the pointer brightening pass.");

namespace anvill {

// Optimize a module. This can be a module with semantics code, lifted
// code, etc.
void OptimizeModule(const EntityLifter &lifter_context,
                    const remill::Arch *arch, const Program &program,
                    llvm::Module &module, const LifterOptions &options) {

  if (auto err = module.materializeAll(); remill::IsError(err)) {
    LOG(FATAL) << remill::GetErrorString(err);
  }

  if (auto used = module.getGlobalVariable("llvm.used"); used) {
    used->setLinkage(llvm::GlobalValue::PrivateLinkage);
    used->eraseFromParent();
  }

  LOG(INFO) << "Optimizing module.";

  if (auto memory_escape = module.getFunction(kMemoryPointerEscapeFunction)) {
    for (auto call : remill::CallersOf(memory_escape)) {
      call->eraseFromParent();
    }
    memory_escape->eraseFromParent();
  }

  llvm::legacy::PassManager mpm;
  mpm.add(llvm::createFunctionInliningPass(250));
  mpm.add(llvm::createGlobalOptimizerPass());
  mpm.add(llvm::createGlobalDCEPass());
  mpm.add(llvm::createStripDeadDebugInfoPass());
  mpm.run(module);

  llvm::legacy::FunctionPassManager fpm(&module);
  fpm.add(llvm::createDeadCodeEliminationPass());
  fpm.add(llvm::createSinkingPass());
  fpm.add(llvm::createNewGVNPass());
  fpm.add(llvm::createSCCPPass());
  fpm.add(llvm::createDeadStoreEliminationPass());
  fpm.add(llvm::createSROAPass());
  fpm.add(llvm::createEarlyCSEPass(true));
  fpm.add(llvm::createBitTrackingDCEPass());
  fpm.add(llvm::createCFGSimplificationPass());
  fpm.add(llvm::createSinkingPass());
  fpm.add(llvm::createCFGSimplificationPass());
  fpm.add(llvm::createInstructionCombiningPass());

  auto error_manager_ptr = ITransformationErrorManager::Create();
  auto &err_man = *error_manager_ptr.get();

  fpm.add(CreateSinkSelectionsIntoBranchTargets(err_man));
  fpm.add(CreateRemoveUnusedFPClassificationCalls());
  fpm.add(CreateRemoveDelaySlotIntrinsics());
  fpm.add(CreateRemoveErrorIntrinsics());
  fpm.add(CreateLowerRemillMemoryAccessIntrinsics());
  fpm.add(CreateRemoveCompilerBarriers());
  fpm.add(CreateLowerTypeHintIntrinsics());
  fpm.add(CreateInstructionFolderPass(err_man));
  fpm.add(llvm::createDeadCodeEliminationPass());
  fpm.add(CreateRecoverEntityUseInformation(err_man, lifter_context));
  fpm.add(CreateSinkSelectionsIntoBranchTargets(err_man));
  fpm.add(CreateRemoveTrivialPhisAndSelects());
  fpm.add(llvm::createDeadCodeEliminationPass());
  fpm.add(CreateRecoverStackFrameInformation(err_man, options));
  fpm.add(llvm::createSROAPass());
  fpm.add(CreateSplitStackFrameAtReturnAddress(err_man));
  fpm.add(llvm::createSROAPass());

  // Sometimes we have a values in the form of (expr ^ 1) used as branch
  // conditions or other targets. Try to fix these to be CMPs, since it
  // makes code easier to read and analyze. This is a fairly narrow optimization
  // but it comes up often enough for lifted code.
  fpm.add(CreateConvertXorToCmp());

  if (FLAGS_pointer_brighten_gas) {
    fpm.add(CreateBrightenPointerOperations(FLAGS_pointer_brighten_gas));
  }

  fpm.doInitialization();
  for (auto &func : module) {
    fpm.run(func);
  }
  fpm.doFinalization();

  // We can extend error handling here to provide more visibility
  // into what has happened
  for (const auto &error : err_man.ErrorList()) {
    std::stringstream buffer;
    buffer << error.description;

    // If this is a fatal error, also include the module IR if
    // available, both before and after the transformation
    if (error.severity == SeverityType::Fatal) {
      buffer << "\n";

      if (error.func_before.has_value()) {
        buffer << "Module IR before the transformation follows\n";
        buffer << error.func_before.value();
      } else {
        buffer << "No pre-transformation module IR available.";
      }

      buffer << "\n";

      if (error.func_after.has_value()) {
        buffer << "Module IR after the transformation follows\n";
        buffer << error.func_after.value();
      } else {
        buffer << "No post-transformation module IR available.";
      }
    }

    auto message = buffer.str();

    // TODO: Maybe create a structured JSON report instead?
    switch (error.severity) {
      case SeverityType::Information: LOG(INFO) << message; break;
      case SeverityType::Warning: LOG(WARNING) << message; break;
      case SeverityType::Error: LOG(ERROR) << message; break;
      case SeverityType::Fatal: LOG(FATAL) << message; break;
    }
  }

  CHECK(!err_man.HasFatalError());

  fpm.add(CreateTransformRemillJumpIntrinsics(lifter_context));
  fpm.add(CreateRemoveRemillFunctionReturns(lifter_context));
  fpm.add(CreateLowerRemillUndefinedIntrinsics());
  fpm.doInitialization();
  for (auto &func : module) {
    fpm.run(func);
  }
  fpm.doFinalization();

  // Get rid of all final uses of `__anvill_pc`.
  if (auto anvill_pc = module.getGlobalVariable(::anvill::kSymbolicPCName)) {
    remill::ReplaceAllUsesOfConstant(
        anvill_pc, llvm::Constant::getNullValue(anvill_pc->getType()), &module);
  }

  CHECK(remill::VerifyModule(&module));
}

}  // namespace anvill
