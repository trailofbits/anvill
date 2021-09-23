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

#include "anvill/Decl.h"

#include <anvill/ITypeSpecification.h>
#include <anvill/Lifters/DeclLifter.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Demangle/Demangle.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Util.h>

#include "Arch/Arch.h"

namespace anvill {

// Declare this global variable in an LLVM module.
llvm::GlobalVariable *
GlobalVarDecl::DeclareInModule(const std::string &name,
                               llvm::Module &target_module,
                               bool allow_unowned) const {
  if (!allow_unowned && !owner) {
    return nullptr;
  }

  auto &context = target_module.getContext();
  auto var_type = remill::RecontextualizeType(type, context);

  auto existing_var = target_module.getGlobalVariable(name);
  if (existing_var && existing_var->getValueType() == var_type) {
    return existing_var;
  }

  return new llvm::GlobalVariable(target_module, var_type, false,
                                  llvm::GlobalValue::ExternalLinkage, nullptr,
                                  name);
}

// Declare this function in an LLVM module.
llvm::Function *FunctionDecl::DeclareInModule(const std::string &name,
                                              llvm::Module &target_module,
                                              bool allow_unowned) const {
  if (!allow_unowned && !owner) {
    return nullptr;
  }

  auto &context = target_module.getContext();
  auto func_type = llvm::dyn_cast<llvm::FunctionType>(
      remill::RecontextualizeType(type, context));

  auto existing_func = target_module.getFunction(name);
  if (existing_func && existing_func->getFunctionType() == func_type) {
    return existing_func;
  }

  DLOG_IF(ERROR, existing_func)
      << "Re-defining " << name << "; previous version has type "
      << remill::LLVMThingToString(existing_func->getFunctionType())
      << " whereas new version has type "
      << remill::LLVMThingToString(func_type);

  llvm::Function *func = llvm::Function::Create(
      func_type, llvm::GlobalValue::ExternalLinkage, name, &target_module);
  DCHECK_EQ(func->getName().str(), name);

  func->addFnAttr(llvm::Attribute::NoInline);

  if (is_noreturn) {
    func->addFnAttr(llvm::Attribute::NoReturn);
  }

  func->setCallingConv(calling_convention);

  // Give them all nice names :-D
  auto arg_num = 0u;
  for (auto &arg : func->args()) {
    arg.setName(params[arg_num++].name);
  }

  return func;
}

// Create a call to this function from within a basic block in a
// lifted bitcode function. Returns the new value of the memory
// pointer.
llvm::Value *FunctionDecl::CallFromLiftedBlock(
    const std::string &name, const remill::IntrinsicTable &intrinsics,
    llvm::BasicBlock *block, llvm::Value *state_ptr, llvm::Value *mem_ptr,
    bool allow_unowned) const {

  if (!allow_unowned && !owner) {
    return llvm::UndefValue::get(mem_ptr->getType());
  }

  auto module = block->getModule();
  auto func = DeclareInModule(name, *module, allow_unowned);
  llvm::IRBuilder<> ir(block);

  // Go and get a pointer to the stack pointer register, so that we can
  // later store our computed return value stack pointer to it.
  auto sp_reg = arch->RegisterByName(arch->StackPointerRegisterName());
  const auto ptr_to_sp = sp_reg->AddressOf(state_ptr, block);
  ir.SetInsertPoint(block);

  // Go and compute the value of the stack pointer on exit from
  // the function, which will be based off of the register state
  // on entry to the function.
  auto new_sp_base = return_stack_pointer->AddressOf(state_ptr, block);
  ir.SetInsertPoint(block);

  const auto sp_val_on_exit = ir.CreateAdd(
      ir.CreateLoad(new_sp_base),
      llvm::ConstantInt::get(return_stack_pointer->type,
                             static_cast<uint64_t>(return_stack_pointer_offset),
                             true));

  llvm::SmallVector<llvm::Value *, 4> param_vals;

  // Get the return address.
  auto ret_addr =
      LoadLiftedValue(return_address, intrinsics, block, state_ptr, mem_ptr);

  // Get the parameters.
  for (const auto &param_decl : params) {
    const auto val =
        LoadLiftedValue(param_decl, intrinsics, block, state_ptr, mem_ptr);
    if (auto inst_val = llvm::dyn_cast<llvm::Instruction>(val)) {
      inst_val->setName(param_decl.name);
    }
    param_vals.push_back(val);
  }

  auto ret_val = ir.CreateCall(func, param_vals);
  (void) ret_val;

  // There is a single return value, store it to the lifted state.
  if (returns.size() == 1) {
    mem_ptr = StoreNativeValue(ret_val, returns.front(), intrinsics, block,
                               state_ptr, mem_ptr);

  // There are possibly multiple return values (or zero). Unpack the
  // return value (it will be a struct type) into its components and
  // write each one out into the lifted state.
  } else {
    unsigned index = 0;
    for (const auto &ret_decl : returns) {
      unsigned indexes[] = {index};
      auto elem_val = ir.CreateExtractValue(ret_val, indexes);
      mem_ptr = StoreNativeValue(elem_val, ret_decl, intrinsics, block,
                                 state_ptr, mem_ptr);
      index += 1;
    }
  }

  // Store the return address, and computed return stack pointer.
  ir.SetInsertPoint(block);
  ir.CreateStore(ret_addr, remill::FindVarInFunction(block, "NEXT_PC"));
  ir.CreateStore(sp_val_on_exit, ptr_to_sp);

  if (is_noreturn) {
    return llvm::UndefValue::get(mem_ptr->getType());
  } else {
    return mem_ptr;
  }
}

#if __has_include(<llvm/Support/JSON.h>)

// Serialize a FunctionDecl to JSON
llvm::json::Object
FunctionDecl::SerializeToJSON(const llvm::DataLayout &dl) const {
  llvm::json::Object json;

  if (address) {
    json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("address"),
                                       static_cast<int64_t>(this->address)});
  }

  json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("is_variadic"),
                                     this->is_variadic});

  json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("is_noreturn"),
                                     this->is_noreturn});

  json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("has_return_address"), this->has_return_address});

  llvm::json::Array params_json;
  for (const auto &pdecl : params) {
    llvm::json::Value v = llvm::json::Value(pdecl.SerializeToJSON(dl));
    params_json.push_back(v);
  }
  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("parameters"),
                             llvm::json::Value(std::move(params_json))});

  llvm::json::Array returns_json;
  for (const auto &rdecl : returns) {
    returns_json.push_back(llvm::json::Value(rdecl.SerializeToJSON(dl)));
  }
  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("return_values"),
                             llvm::json::Value(std::move(returns_json))});

  if (return_stack_pointer) {
    llvm::json::Object return_stack_pointer_json;
    return_stack_pointer_json.insert(llvm::json::Object::KV{
        llvm::json::ObjectKey("register"), this->return_stack_pointer->name});
    return_stack_pointer_json.insert(llvm::json::Object::KV{
        llvm::json::ObjectKey("offset"), this->return_stack_pointer_offset});
    return_stack_pointer_json.insert(
        llvm::json::Object::KV{llvm::json::ObjectKey("type"),
                               ITypeSpecification::TypeToString(
                                   *this->return_stack_pointer->type, dl)});

    json.insert(llvm::json::Object::KV{
        llvm::json::ObjectKey("return_stack_pointer"),
        llvm::json::Value(std::move(return_stack_pointer_json))});
  }

  json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("return_address"),
      llvm::json::Value(return_address.SerializeToJSON(dl))});

  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("calling_convention"),
                             llvm::json::Value(calling_convention)});

  return json;
}

// Serialize a ParameterDecl to JSON
llvm::json::Object
ParameterDecl::SerializeToJSON(const llvm::DataLayout &dl) const {

  // Get the serialization for the ValueDecl
  llvm::json::Object param_json = this->ValueDecl::SerializeToJSON(dl);

  // Insert "name"
  param_json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("name"), this->name});

  return param_json;
}

// Serialize a ValueDecl to JSON
llvm::json::Object
ValueDecl::SerializeToJSON(const llvm::DataLayout &dl) const {
  llvm::json::Object value_json;

  if (reg) {

    // The value is in a register
    value_json.insert(
        llvm::json::Object::KV{llvm::json::ObjectKey("register"), reg->name});
  } else if (mem_reg) {

    // The value is in memory
    llvm::json::Object memory_json;
    memory_json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("register"),
                                              mem_reg->name});
    memory_json.insert(
        llvm::json::Object::KV{llvm::json::ObjectKey("offset"), mem_offset});

    // Wrap the memory_json structure in a memory block
    value_json.insert(
        llvm::json::Object::KV{llvm::json::ObjectKey("memory"),
                               llvm::json::Value(std::move(memory_json))});
  } else {
    LOG(FATAL) << "Trying to serialize a value that has not been allocated";
  }

  value_json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("type"),
                             ITypeSpecification::TypeToString(*type, dl)});

  return value_json;
}
#endif

// Create a Function Declaration from an `llvm::Function`.
llvm::Expected<FunctionDecl> FunctionDecl::Create(llvm::Function &func,
                                                  const remill::Arch *arch) {

  FunctionDecl decl;
  decl.arch = arch;
  decl.type = func.getFunctionType();
  decl.is_variadic = func.isVarArg();
  decl.is_noreturn = func.hasFnAttribute(llvm::Attribute::NoReturn);
  decl.has_return_address = true;

  // If the function calling convention is not the default llvm::CallingConv::C
  // then use it. Otherwise, get the CallingConvention from the remill::Arch
  std::unique_ptr<CallingConvention> cc;
  llvm::CallingConv::ID cc_id = func.getCallingConv();

  // The value is not default so use it.
  if (cc_id != llvm::CallingConv::C) {
    auto maybe_cc = CallingConvention::CreateCCFromCCID(cc_id, arch);
    if (remill::IsError(maybe_cc)) {
      const auto sub_error = remill::GetErrorString(maybe_cc);
      return llvm::createStringError(
          std::make_error_code(std::errc::invalid_argument),
          "Calling convention of function '%s' is not supported: %s",
          func.getName().str().c_str(), sub_error.c_str());
    } else {
      remill::GetReference(maybe_cc).swap(cc);
    }

  // Figure out the default calling convention for this triple.
  } else {
    auto maybe_cc = CallingConvention::CreateCCFromArch(arch);
    if (remill::IsError(maybe_cc)) {
      const auto sub_error = remill::GetErrorString(maybe_cc);
      return llvm::createStringError(
          std::make_error_code(std::errc::invalid_argument),
          "Calling convention of function '%s' is not supported: %s",
          func.getName().str().c_str(), sub_error.c_str());
    } else {
      remill::GetReference(maybe_cc).swap(cc);
    }
  }

  auto err = cc->AllocateSignature(decl, func);
  if (remill::IsError(err)) {
    return std::move(err);
  }

  decl.calling_convention = cc->getIdentity();

  return decl;
}

}  // namespace anvill
