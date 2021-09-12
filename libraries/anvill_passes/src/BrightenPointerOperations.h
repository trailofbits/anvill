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
#include <llvm/IR/PassManager.h>

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

class PointerLifterPass final : public llvm::PassInfoMixin<PointerLifterPass> {
 public:
  explicit PointerLifterPass(unsigned max_gas_);

  llvm::PreservedAnalyses run(llvm::Function &f,
                              llvm::FunctionAnalysisManager &fam);

 private:
  const unsigned max_gas;
};

class PointerLifter
    : public llvm::InstVisitor<PointerLifter, std::pair<llvm::Value *, bool>> {
 public:
  // this is my one requirement: I call a function, get a function pass.
  // I can pass that function a cross-reference resolver instance, and
  // when you get to an llvm::Constant, it will use the xref resolver on that
  PointerLifter(llvm::Function *func_, unsigned max_gas_);

  // ReplaceAllUses - swaps uses of LLVM inst with other LLVM inst
  // Adds users to the next worklist, for downstream type propagation
  void ReplaceAllUses(llvm::Value *orig_inst, llvm::Value *new_inst);

  // We need to get a pointer from some value
  llvm::Value *getPointerToValue(llvm::IRBuilder<> &ir, llvm::Value *curr_val,
                                 llvm::Type *dest_type);


  std::pair<llvm::Value *, bool> visitIntToPtrInst(llvm::IntToPtrInst &inst);
  std::pair<llvm::Value *, bool> visitLoadInst(llvm::LoadInst &inst);
  std::pair<llvm::Value *, bool> visitReturnInst(llvm::ReturnInst& inst);
  std::pair<llvm::Value *, bool> visitStoreInst(llvm::StoreInst& store);
  std::pair<llvm::Value *, bool> visitAllocaInst(llvm::AllocaInst& alloca);

  std::pair<llvm::Value *, bool> visitSExtInst(llvm::SExtInst& inst);
  std::pair<llvm::Value *, bool> visitZExtInst(llvm::ZExtInst& inst);

  std::pair<llvm::Value *, bool> visitCmpInst(llvm::CmpInst& inst);
  llvm::Value* flattenGEP(llvm::GetElementPtrInst *gep);
  std::pair<llvm::Value *, bool> BrightenGEP_PeelLastIndex(llvm::GetElementPtrInst *dst,
                            llvm::Type *inferred_type);
  std::pair<llvm::Value *, bool> visitGetElementPtrInst(llvm::GetElementPtrInst &inst);
  std::pair<llvm::Value *, bool> visitBitCastInst(llvm::BitCastInst &inst);
  std::pair<llvm::Value *, bool> visitPHINode(llvm::PHINode &inst);
  std::pair<llvm::Value *, bool> visitPtrToIntInst(llvm::PtrToIntInst& inst);
  // Simple wrapper for storing the type information into the list, and then
  // calling visit.
  std::pair<llvm::Value *, bool> visitInferInst(llvm::Instruction *inst, llvm::Type *inferred_type);
  std::pair<llvm::Value *, bool> visitInstruction(llvm::Instruction &I);
  std::pair<llvm::Value *, bool>
  visitBinaryOperator(llvm::BinaryOperator &inst);

  llvm::Value *GetIndexedPointer(llvm::IRBuilder<> &ir, llvm::Value *address,
                                 llvm::Value *offset, llvm::Type *t) const;

  // Driver method
  void LiftFunction(llvm::Function &func, llvm::FunctionAnalysisManager &fam);

 private:
  // Maximum number of iterations that `LiftFunction` is allowed to perform.
  const unsigned max_gas;

  std::unordered_map<llvm::Value *, llvm::Type *> inferred_types;
  std::unordered_map<llvm::Value *, llvm::Type *> next_inferred_types;

  std::unordered_set<llvm::Instruction *> to_remove;
  std::unordered_map<llvm::Instruction *, llvm::Value *> rep_map;
  std::unordered_map<llvm::Instruction *, bool> dead_inst;

  // Whether or not progress has been made, e.g. a new type was inferred.
  bool made_progress{false};

  llvm::Function *const func;
  llvm::Module *const mod;
  llvm::LLVMContext &context;
  llvm::IntegerType *const i32_ty;
  llvm::IntegerType *const i8_ty;
  llvm::PointerType *const i8_ptr_ty;
  const llvm::DataLayout &dl;
};

}  // namespace anvill
