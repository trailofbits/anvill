/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Providers.h>
#include <anvill/Declarations.h>
#include <glog/logging.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Type.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/Util.h>

#include "Specification.h"

namespace anvill {

TypeProvider::~TypeProvider(void) {}

// Try to return the type of a function starting at address `address`. This
// type is the prototype of the function.
std::optional<FunctionDecl>
NullTypeProvider::TryGetFunctionType(uint64_t) const {
  return std::nullopt;
}

std::optional<VariableDecl>
NullTypeProvider::TryGetVariableType(uint64_t) const {
  return std::nullopt;
}

// Try to return the type of a function starting at address `to_address`. This
// type is the prototype of the function. The type can be call site specific,
// where the call site is `from_inst`.
std::optional<CallableDecl> TypeProvider::TryGetCalledFunctionType(
    uint64_t function_address, const remill::Instruction &from_inst,
    uint64_t to_address) const {
  if (auto decl = TryGetCalledFunctionType(function_address, from_inst)) {
    return decl;
  } else if (auto func_decl = TryGetFunctionType(to_address)) {
    return static_cast<CallableDecl &>(func_decl.value());
  } else {
    return std::nullopt;
  }
}

// Try to return the type of a function that has been called from `from_isnt`.
std::optional<CallableDecl> TypeProvider::TryGetCalledFunctionType(
    uint64_t function_address, const remill::Instruction &) const {
  return std::nullopt;
}

TypeProvider::TypeProvider(const ::anvill::TypeDictionary &type_dictionary_)
    : context(type_dictionary_.u.named.bool_->getContext()),
      type_dictionary(type_dictionary_) {}

// Try to get the type of the register named `reg_name` on entry to the
// instruction at `inst_address` inside the function beginning at
// `func_address`.
void TypeProvider::QueryRegisterStateAtInstruction(
    uint64_t, uint64_t,
    std::function<void(const std::string &, llvm::Type *,
                       std::optional<uint64_t>)>) const {}

SpecificationTypeProvider::~SpecificationTypeProvider(void) {}

SpecificationTypeProvider::SpecificationTypeProvider(
    const Specification &spec)
    : TypeProvider(spec.impl->type_translator),
      impl(spec.impl) {}

// Try to return the type of a function that has been called from `from_isnt`.
std::optional<CallableDecl> SpecificationTypeProvider::TryGetCalledFunctionType(
    uint64_t function_address,
    const remill::Instruction &from_inst) const {
  std::pair<std::uint64_t, std::uint64_t> loc{function_address,
                                              from_inst.pc};

  auto cs_it = impl->loc_to_call_site.find(loc);
  if (cs_it == impl->loc_to_call_site.end()) {
    return std::nullopt;
  } else {
    return *(cs_it->second);
  }
}

// Try to return the type of a function starting at address `address`. This
// type is the prototype of the function.
std::optional<anvill::FunctionDecl>
SpecificationTypeProvider::TryGetFunctionType(uint64_t address) const {
  auto func_it = impl->address_to_function.find(address);
  if (func_it == impl->address_to_function.end()) {
    return std::nullopt;
  } else {
    return *(func_it->second);
  }
}

std::optional<anvill::VariableDecl>
SpecificationTypeProvider::TryGetVariableType(uint64_t address) const {
  auto var_it = impl->address_to_var.find(address);
  if (var_it != impl->address_to_var.end()) {
    return *(var_it->second);
  } else {
    return std::nullopt;
  }
}


    // Try to return the type of a function that has been called from `from_isnt`.
    std::optional<CallableDecl> DefaultCallableTypeProvider::TryGetCalledFunctionType(
        uint64_t function_address,
        const remill::Instruction &from_inst) const {
          return this->decl;
        }


    // Try to return the type of a function starting at address `address`. This
    // type is the prototype of the function.
    std::optional<anvill::FunctionDecl> DefaultCallableTypeProvider::TryGetFunctionType(
        uint64_t address) const {
          return std::nullopt;
        }

    std::optional<anvill::VariableDecl>
      DefaultCallableTypeProvider::TryGetVariableType(uint64_t address) const {
        return std::nullopt;
      }

      DefaultCallableTypeProvider::DefaultCallableTypeProvider(CallableDecl decl, const TypeTranslator &tt): TypeProvider(tt), decl(decl) {

      }

}  // namespace anvill
