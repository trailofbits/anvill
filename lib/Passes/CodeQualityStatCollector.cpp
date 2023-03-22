
#define DEBUG_TYPE "code_quality"

#include <anvill/ABI.h>
#include <anvill/Passes/CodeQualityStatCollector.h>
#include <llvm/ADT/Statistic.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>

namespace anvill {
ALWAYS_ENABLED_STATISTIC(
    ConditionalComplexity,
    "A factor that approximates the complexity of the condition in branch instructions");
ALWAYS_ENABLED_STATISTIC(NumberOfInstructions, "Total number of instructions");
ALWAYS_ENABLED_STATISTIC(AbruptControlFlow, "Indirect control flow instructions");
ALWAYS_ENABLED_STATISTIC(IntToPointerCasts, "Integer to pointer casts");
ALWAYS_ENABLED_STATISTIC(PointerToIntCasts, "Pointer to integer casts");
ALWAYS_ENABLED_STATISTIC(AnvillStackPointers, "Number of functions that expose an Anvill stack pointer");
ALWAYS_ENABLED_STATISTIC(AnvillPCPointers, "Number of functions that expose an Anvill pc pointer");


namespace {
// The idea here is that we count the number of boolean expressions involved in this branch which should be an indicator of its complexity
class ConditionalComplexityVisitor
    : public llvm::InstVisitor<ConditionalComplexityVisitor> {

 public:
  void tryVisit(llvm::Value *v) {
    if (auto *insn = llvm::dyn_cast<llvm::Instruction>(v)) {
      this->visit(insn);
    }
  }

  void visitBinaryOperator(llvm::BinaryOperator &I) {
    if (auto *inttype = llvm::dyn_cast<llvm::IntegerType>(I.getType())) {
      if (inttype->getBitWidth() == 1) {
        ++ConditionalComplexity;
        this->tryVisit(I.getOperand(0));
        this->tryVisit(I.getOperand(1));
      }
    }
  }

  void visitCmpInst(llvm::CmpInst &I) {
    ++ConditionalComplexity;
  }

  void visitUnaryOperator(llvm::UnaryOperator &I) {
    if (auto *inttype = llvm::dyn_cast<llvm::IntegerType>(I.getType())) {
      ++ConditionalComplexity;
      this->tryVisit(I.getOperand(0));
    }
  }
};
}  // namespace


llvm::PreservedAnalyses
CodeQualityStatCollector::run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &analysisManager) {
  ConditionalComplexityVisitor complexity_visitor;
  llvm::GlobalVariable* anvill_sp = module.getGlobalVariable(kSymbolicSPName);
  llvm::GlobalVariable* anvill_pc = module.getGlobalVariable(kSymbolicPCName);

  llvm::DenseSet<const llvm::Function*> sp_funcs;
  llvm::DenseSet<const llvm::Function*> pc_funcs;

  if (anvill_sp != nullptr) {
    for (const auto &U: anvill_sp->uses()) {
      const auto &user = U.getUser();
      if (const llvm::Instruction *I = llvm::dyn_cast<llvm::Instruction>(user)) {
        if (!sp_funcs.count(I->getFunction())) {
          ++AnvillStackPointers;
          sp_funcs.insert(I->getFunction());
        }
      }
    }
  }

  if (anvill_pc != nullptr) {
    for (const auto &U: anvill_pc->uses()) {
      const auto &user = U.getUser();
      if (const llvm::Instruction *I = llvm::dyn_cast<llvm::Instruction>(user)) {
        if (!pc_funcs.count(I->getFunction())) {
          ++AnvillPCPointers;
          pc_funcs.insert(I->getFunction());
        }
      }
    }
  }

  for (auto &function : module) {
    for (auto &i : llvm::instructions(function)) {
      if (auto *int_to_ptr = llvm::dyn_cast<llvm::IntToPtrInst>(&i)) {
        ++IntToPointerCasts;
      }

      if (auto *int_to_ptr = llvm::dyn_cast<llvm::PtrToIntInst>(&i)) {
        ++PointerToIntCasts;
      }

      ++NumberOfInstructions;
      if (auto *branch = llvm::dyn_cast<llvm::BranchInst>(&i)) {
        if (branch->isConditional()) {
          complexity_visitor.tryVisit(branch->getCondition());
        }
      }

      if (auto *cb = llvm::dyn_cast<llvm::CallBase>(&i)) {
        auto target = cb->getCalledFunction();
        if (target != nullptr) {
          if (target->getName() == kAnvillSwitchCompleteFunc ||
              target->getName() == kAnvillSwitchIncompleteFunc) {
            ++AbruptControlFlow;
          }
        }
      }
    }
  }
  return llvm::PreservedAnalyses::all();
}

llvm::StringRef CodeQualityStatCollector::name(void) {
  return "CodeQualityStatCollector";
}

}  // namespace anvill
