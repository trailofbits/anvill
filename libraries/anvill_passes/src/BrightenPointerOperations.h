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

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

#include <algorithm>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace llvm {
class DataLayout;
class Function;
class IntegerType;
class LLVMContext;
class Module;
class PointerType;
class Type;
class Value;
}  // namespace llvm
namespace anvill {

class CrossReferenceResolver;

class PointerLifterPass final : public llvm::FunctionPass {
 public:
  explicit PointerLifterPass(unsigned max_gas_);

  bool runOnFunction(llvm::Function &f) final;

 private:
  static char ID;
  const unsigned max_gas;
};

class PointerLifter
    : public llvm::InstVisitor<PointerLifter, std::tuple<llvm::Value *, bool, bool>> {
 public:
  // this is my one requirement: I call a function, get a function pass.
  // I can pass that function a cross-reference resolver instance, and
  // when you get to an llvm::Constant, it will use the xref resolver on that
  PointerLifter(llvm::Function *func_, unsigned max_gas_);

  // ReplaceAllUses - swaps uses of LLVM inst with other LLVM inst
  // Adds users to the next worklist, for downstream type propagation
  void ReplaceAllUses(llvm::Value *orig_inst, llvm::Value *new_inst);

  std::tuple<llvm::Value *, bool, bool> visitIntToPtrInst(llvm::IntToPtrInst &inst);
  std::tuple<llvm::Value *, bool, bool> visitLoadInst(llvm::LoadInst &inst);
  std::tuple<llvm::Value *, bool, bool> visitReturnInst(llvm::ReturnInst& inst);
  std::tuple<llvm::Value *, bool, bool> visitStoreInst(llvm::StoreInst& store);
  std::tuple<llvm::Value *, bool, bool> visitAllocaInst(llvm::AllocaInst& alloca);
  
  std::tuple<llvm::Value *, bool, bool> visitSExtInst(llvm::SExtInst& inst);
  std::tuple<llvm::Value *, bool, bool> visitZExtInst(llvm::ZExtInst& inst);

  std::tuple<llvm::Value *, bool, bool> visitCmpInst(llvm::CmpInst& inst);
  llvm::Value* flattenGEP(llvm::GetElementPtrInst *gep);
  std::tuple<llvm::Value *, bool, bool> BrightenGEP_PeelLastIndex(llvm::GetElementPtrInst *dst,
                            llvm::Type *inferred_type);
  std::tuple<llvm::Value *, bool, bool> visitGetElementPtrInst(llvm::GetElementPtrInst &inst);
  std::tuple<llvm::Value *, bool, bool> visitBitCastInst(llvm::BitCastInst &inst);
  std::tuple<llvm::Value *, bool, bool> visitPHINode(llvm::PHINode &inst);
  std::tuple<llvm::Value *, bool, bool> visitPtrToIntInst(llvm::PtrToIntInst& inst);
  // Simple wrapper for storing the type information into the list, and then
  // calling visit.
  std::tuple<llvm::Value *, bool, bool> visitInferInst(llvm::Instruction *inst, llvm::Type *inferred_type);
  std::tuple<llvm::Value *, bool, bool> visitInstruction(llvm::Instruction &I);
  std::tuple<llvm::Value *, bool, bool> visitBinaryOperator(llvm::BinaryOperator &inst);

  std::tuple<llvm::Value *, bool, bool> createCast(llvm::Value* inst, llvm::Type* dest_ty);
  std::tuple<llvm::Value *, bool, bool> createLoad(llvm::Value* inst, llvm::Type* dest_ty);
  std::tuple<llvm::Value *, bool, bool> createGEP(llvm::Value* address, llvm::Value* offset, llvm::Type* dest_type);
  std::tuple<llvm::Value *, bool, bool> createPHI(llvm::PHINode* src, llvm::Type* dest);

  std::tuple<llvm::Value *, bool, bool> GetIndexedPointer(llvm::IRBuilder<> &ir, llvm::Value *address,
                                 llvm::Value *offset, llvm::Type *t);

  // Driver method
  void LiftFunction(llvm::Function &func);

 private:
  // Maximum number of iterations that `LiftFunction` is allowed to perform.
  const unsigned max_gas;

  std::unordered_map<llvm::Value *, llvm::Type *> inferred_types;
  std::unordered_map<llvm::Value *, llvm::Type *> next_inferred_types;

  std::unordered_set<llvm::Instruction *> to_remove;
  std::unordered_map<llvm::Instruction *, llvm::Value *> rep_map;
  std::unordered_map<llvm::Instruction *, bool> dead_inst;

  // TODO (Carson) Merge these together somehow? 
  using EquivalenceClass = std::unordered_map<llvm::Type* , llvm::Value *>;
  std::unordered_map<llvm::Value *, std::shared_ptr<EquivalenceClass>> equiv_cache2;
  std::unordered_map<llvm::Value *, std::unordered_map<llvm::Type*, llvm::Value *>> phi_cache;
  std::unordered_map<llvm::Value *, std::unordered_map<llvm::Type*, llvm::Value *>> load_cache;
  std::unordered_map<llvm::Value *, std::unordered_map<llvm::Value*, std::unordered_map<llvm::Type*, llvm::Value*>>> gep_cache;
  // Whether or not progress has been made, e.g. a new type was inferred.
  bool made_progress{false};

  llvm::Function *const func;
  llvm::Module *const mod;
  llvm::LLVMContext &context;
  llvm::IntegerType * i32_ty;
  llvm::IntegerType * i8_ty;
  llvm::PointerType * i8_ptr_ty;
  const llvm::DataLayout &dl;
};

}  // namespace anvill
