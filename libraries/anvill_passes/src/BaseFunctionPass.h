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

#include <anvill/ABI.h>
#include <anvill/Analysis/Utils.h>
#include <anvill/ITransformationErrorManager.h>
#include <anvill/Result.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>

#include <magic_enum.hpp>
#include <sstream>
#include <unordered_set>

#include "Utils.h"

namespace anvill {

// BaseFunctionPass error codes
enum class BaseFunctionPassErrorCode {

  // The name of the requested symbolic value does not start with the
  // required `__anvill_` prefix
  InvalidSymbolicValueName,

  // A symbolic value with the same name but different
  // type already exists
  SymbolicValueConflict,
};

template <typename UserFunctionPass>
class BaseFunctionPass : public llvm::PassInfoMixin<UserFunctionPass> {

  // Current module.
  llvm::Module *module{nullptr};

  // Current function.
  llvm::Function *function{nullptr};

  // Module name
  std::string original_module_name;

  // Module IR, before the function pass
  std::string original_function_ir;

  // Current function name
  std::string original_function_name;

 protected:
  // Error manager, used for reporting
  ITransformationErrorManager &error_manager;

 public:
  BaseFunctionPass(ITransformationErrorManager &error_manager_);
  virtual ~BaseFunctionPass(void) = default;

  // Function pass entry point, called by LLVM
  llvm::PreservedAnalyses run(llvm::Function &function,
                              llvm::FunctionAnalysisManager &fam);

  // Returns true if this instruction references the stack pointer
  static bool
  InstructionReferencesStackPointer(llvm::Module *module,
                                    const llvm::Instruction &instr);

  // Returns true if this is either a store or a load instruction
  static bool IsMemoryOperation(const llvm::Instruction &instr);

  // Creates or returns an existing symbolic value
  static Result<llvm::GlobalVariable *, BaseFunctionPassErrorCode>
  GetSymbolicValue(llvm::Module &module, llvm::Type *type,
                   const std::string &name);

  // Converts the given enum value to string
  template <typename ErrorCodeEnum>
  static std::string EnumValueToString(ErrorCodeEnum error_code);

  // Emits an error through the transformation error manager
  template <typename ErrorCodeEnum>
  void EmitError(SeverityType severity, ErrorCodeEnum error_code,
                 const std::string &message,
                 llvm::Instruction *instr = nullptr);

  // A list of llvm::Instruction pointers
  using InstructionList = std::vector<llvm::Instruction *>;

  // A list of llvm::User pointers
  using UserList = std::vector<llvm::User *>;

  // Returns a list of the instructions matching the given types
  template <class... Types>
  static InstructionList SelectInstructions(llvm::Function &function);

  // Tracks down all the direct and indirect users of source_instr that are
  // of the requested type
  template <class... Types>
  static UserList TrackUsersOf(llvm::User *initial_user);

  // Compatibility method for LLVM < 12
  static llvm::StructType *getTypeByName(const llvm::Module &module,
                                         llvm::StringRef name);
};

template <typename UserFunctionPass>
BaseFunctionPass<UserFunctionPass>::BaseFunctionPass(
    ITransformationErrorManager &error_manager_)
    : error_manager(error_manager_) {}

template <typename UserFunctionPass>
llvm::PreservedAnalyses
BaseFunctionPass<UserFunctionPass>::run(llvm::Function &function_,
                                        llvm::FunctionAnalysisManager &) {
  function = &function_;
  module = function->getParent();
  original_function_ir = GetFunctionIR(*function);
  original_module_name = module->getName().str();
  original_function_name = function->getName().str();

  auto &function_pass = *static_cast<UserFunctionPass *>(this);
  return function_pass.Run(*function);
}

template <typename UserFunctionPass>
bool BaseFunctionPass<UserFunctionPass>::InstructionReferencesStackPointer(
    llvm::Module *module, const llvm::Instruction &instr) {

  auto operand_count = instr.getNumOperands();

  for (auto operand_index = 0U; operand_index < operand_count;
       ++operand_index) {

    auto operand = instr.getOperand(operand_index);
    if (IsRelatedToStackPointer(module, operand)) {
      return true;
    }
  }

  return false;
}

template <typename UserFunctionPass>
bool BaseFunctionPass<UserFunctionPass>::IsMemoryOperation(
    const llvm::Instruction &instr) {
  if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(&instr);
      load_inst != nullptr) {
    return true;
  }

  if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(&instr);
      store_inst != nullptr) {
    return true;
  }

  return false;
}


template <typename UserFunctionPass>
Result<llvm::GlobalVariable *, BaseFunctionPassErrorCode>
BaseFunctionPass<UserFunctionPass>::GetSymbolicValue(llvm::Module &module,
                                                     llvm::Type *type,
                                                     const std::string &name) {

  if (name.find(kAnvillNamePrefix) != 0U) {
    return BaseFunctionPassErrorCode::InvalidSymbolicValueName;
  }

  auto symbolic_value = module.getGlobalVariable(name);
  if (symbolic_value != nullptr) {
    if (type != symbolic_value->getValueType()) {
      return BaseFunctionPassErrorCode::SymbolicValueConflict;
    }

  } else {
    auto initial_value = llvm::Constant::getNullValue(type);

    symbolic_value = new llvm::GlobalVariable(
        module, type, false, llvm::GlobalValue::ExternalLinkage, initial_value,
        name);
  }

  return symbolic_value;
}

template <typename UserFunctionPass>
template <typename ErrorCodeEnum>
std::string BaseFunctionPass<UserFunctionPass>::EnumValueToString(
    ErrorCodeEnum error_code) {
  return std::string(magic_enum::enum_name(error_code));
}

template <typename UserFunctionPass>
template <typename ErrorCodeEnum>
void BaseFunctionPass<UserFunctionPass>::EmitError(SeverityType severity,
                                                   ErrorCodeEnum error_code,
                                                   const std::string &message,
                                                   llvm::Instruction *instr) {

  TransformationError error;
  error.pass_name = llvm::PassInfoMixin<UserFunctionPass>::name().str();
  error.severity = severity;
  error.error_code = EnumValueToString(error_code);
  error.message = message;
  error.module_name = original_module_name;
  error.function_name = original_function_name;
  error.func_before = original_function_ir;

  auto current_func_ir = GetFunctionIR(*function);
  if (current_func_ir != error.func_before) {
    error.func_after = current_func_ir;
  }

  std::stringstream buffer;
  buffer << "severity:";

  switch (severity) {
    case SeverityType::Information: buffer << "information"; break;
    case SeverityType::Warning: buffer << "warning"; break;
    case SeverityType::Error: buffer << "error"; break;
    case SeverityType::Fatal: buffer << "fatal"; break;
  }

  buffer << " pass_name:" << error.pass_name
         << " error_code:" << error.error_code
         << " module_name:" << error.module_name;

  if (error.function_name.has_value()) {
    buffer << " function_name:" << error.function_name.value();
  }

  if (instr != nullptr) {
    buffer << " instruction:" << remill::LLVMThingToString(instr);
  }

  buffer << " message:\"" << message << "\"";
  error.description = buffer.str();

  error_manager.Insert(std::move(error));
}

template <typename UserFunctionPass>
template <class... Types>
typename BaseFunctionPass<UserFunctionPass>::InstructionList
BaseFunctionPass<UserFunctionPass>::SelectInstructions(
    llvm::Function &function) {
  InstructionList output;

  for (auto &instruction : llvm::instructions(function)) {
    bool selected = (llvm::dyn_cast<Types>(&instruction) || ...);
    if (selected) {
      output.push_back(&instruction);
    }
  }

  return output;
}

template <typename UserFunctionPass>
template <class... Types>
typename BaseFunctionPass<UserFunctionPass>::UserList
BaseFunctionPass<UserFunctionPass>::TrackUsersOf(llvm::User *initial_user) {
  std::vector<llvm::User *> pending_queue{initial_user};
  std::vector<llvm::User *> user_list;
  std::unordered_set<llvm::User *> visited;

  do {
    auto queue = std::move(pending_queue);
    pending_queue.clear();

    for (auto &instr : queue) {
      for (auto &use : instr->uses()) {
        auto user = use.getUser();
        if (visited.count(user) > 0U) {
          continue;
        }

        visited.insert(user);

        bool selected = (llvm::dyn_cast<Types>(user) || ...);
        if (selected) {
          user_list.push_back(llvm::dyn_cast<llvm::User>(user));
        } else {
          pending_queue.push_back(user);
        }
      }
    }
  } while (!pending_queue.empty());

  return user_list;
}

template <typename UserFunctionPass>
llvm::StructType *
BaseFunctionPass<UserFunctionPass>::getTypeByName(const llvm::Module &module,
                                                  llvm::StringRef name) {
#if LLVM_VERSION_MAJOR >= 12
  auto &context = module.getContext();
  return llvm::StructType::getTypeByName(context, name);

#else
  return module.getTypeByName(name);
#endif
}

}  // namespace anvill
