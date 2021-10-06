#pragma once

#include <anvill/IndirectJumpPass.h>
#include <anvill/SliceInterpreter.h>
#include <anvill/SliceManager.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/ValueMap.h>
#include <llvm/Pass.h>

namespace anvill {

enum CastType { ZEXT, SEXT, NONE };
struct Cast {
  CastType caTy;
  unsigned int toBits;

  llvm::APInt apply(llvm::APInt target) {
    switch (this->caTy) {
      case CastType::ZEXT: return target.zext(this->toBits);
      case CastType::SEXT: return target.sext(this->toBits);
      case CastType::NONE: return target;
    }
  }
};


class PcRel {
 public:
  PcRel(SliceID slice) : slice(slice) {}

  llvm::APInt apply(SliceInterpreter &interp, llvm::APInt loadedVal);


  llvm::IntegerType *getExpectedType(SliceManager &);
  SliceID slice;
};


class IndexRel {
 private:
  SliceID slice;
  llvm::Value *index;

 public:
  llvm::Value *getIndex();
  llvm::APInt apply(SliceInterpreter &interp, llvm::APInt indexValue);

  IndexRel(SliceID slice, llvm::Value *index) : slice(slice), index(index) {}
};

struct Bound {
  llvm::APInt lower;
  llvm::APInt upper;
  bool isSigned;

  bool lessThanOrEqual(llvm::APInt lhs, llvm::APInt rhs) {
    if (isSigned) {
      return lhs.sle(rhs);
    } else {
      return lhs.ule(rhs);
    }
  }
};

struct JumpTableResult {
  PcRel pcRel;
  IndexRel indexRel;
  Bound bounds;
  llvm::BasicBlock *defaultOut;
};

class JumpTableAnalysis : public IndirectJumpPass<JumpTableAnalysis> {

 private:
  SliceManager &slices;
  llvm::ValueMap<llvm::CallInst *, JumpTableResult> results;

 public:
  JumpTableAnalysis(SliceManager &slices)
      : IndirectJumpPass(),
        slices(slices) {}

  llvm::StringRef getPassName() const override;

  void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
  bool runOnIndirectJump(llvm::CallInst *indirectJump);

  std::optional<JumpTableResult>
  getResultFor(llvm::CallInst *indirectJump) const;

  const llvm::ValueMap<llvm::CallInst *, JumpTableResult> &
  getAllResults() const {
    return this->results;
  }
};
}  // namespace anvill
