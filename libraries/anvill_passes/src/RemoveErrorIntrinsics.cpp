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

#include <anvill/Transforms.h>
#include <glog/logging.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

#include <unordered_set>

#include "Utils.h"

namespace anvill {
namespace {

class RemoveErrorIntrinsics final : public llvm::FunctionPass {
 public:
  RemoveErrorIntrinsics(void) : llvm::FunctionPass(ID) {}

  bool runOnFunction(llvm::Function &func) final;

 private:
  static char ID;
};

char RemoveErrorIntrinsics::ID = '\0';

// Try to lower remill error intrinsics.
bool RemoveErrorIntrinsics::runOnFunction(llvm::Function &func) {
  auto module = func.getParent();
  auto error = module->getFunction("__remill_error");

  if (!error) {
    return false;
  }

  auto calls = FindFunctionCalls(func, [=](llvm::CallBase *call) -> bool {
    return call->getCalledFunction() == error;
  });

  std::unordered_set<llvm::Instruction *> removed;
  std::unordered_set<llvm::BasicBlock *> affected_blocks;

  llvm::SmallVector<std::pair<unsigned, llvm::MDNode *>, 16> mds;

  for (llvm::CallBase *call : calls) {
    if (removed.count(call)) {
      continue;
    }

    mds.clear();
    call->getAllMetadata(mds);

    // Work backward through the block, up until we can remove the instruction.
    llvm::BasicBlock * const block = call->getParent();
    affected_blocks.insert(block);

    auto pred_inst = call->getPrevNode();
    for (auto inst = block->getTerminator(); inst != pred_inst; ) {
      const auto next_inst = inst->getPrevNode();
      CHECK_EQ(inst->getParent(), block);

      if (auto itype = inst->getType(); itype && !itype->isVoidTy()) {
        inst->replaceAllUsesWith(llvm::UndefValue::get(itype));
      }

      inst->dropAllReferences();
      inst->eraseFromParent();
      removed.insert(inst);
      inst = next_inst;
    }

    DCHECK(!block->getTerminator());
    auto unreachable_inst = new llvm::UnreachableInst(
        block->getContext(), block);

    for (auto [md_id, md_node] : mds) {
      unreachable_inst->setMetadata(md_id, md_node);
    }
  }

  std::vector<llvm::PHINode *> broken_phis;
  std::vector<llvm::Value *> new_incoming_vals;
  std::vector<llvm::BasicBlock *> new_incoming_blocks;
  std::unordered_set<llvm::BasicBlock *> unreachable_blocks;

  for (auto changed = true; changed; ) {
    changed = false;

    // Find PHI nodes with predecessor blocks that now no longer actually
    // flow to the PHI node.
    broken_phis.clear();
    for (llvm::BasicBlock &block : func) {
      for (llvm::Instruction &inst : block) {
        if (auto phi = llvm::dyn_cast<llvm::PHINode>(&inst)) {
          auto num_incoming_vals = phi->getNumIncomingValues();
          for (auto i = 0u; i < num_incoming_vals; ++i) {
            auto incoming_block = phi->getIncomingBlock(i);
            if (affected_blocks.count(incoming_block)) {
              broken_phis.push_back(phi);
              changed = true;
              break;
            }
          }
        } else {
          break;
        }
      }
    }

    // Rebuild the PHI nodes, or replace them with what should have been passed
    // through.
    for (llvm::PHINode *phi : broken_phis) {
      new_incoming_vals.clear();
      new_incoming_blocks.clear();

      const auto num_incoming_vals = phi->getNumIncomingValues();
      for (auto i = 0u; i < num_incoming_vals; ++i) {
        auto incoming_block = phi->getIncomingBlock(i);
        if (affected_blocks.count(incoming_block)) {
          continue;
        } else {
          new_incoming_vals.push_back(phi->getIncomingValue(i));
          new_incoming_blocks.push_back(incoming_block);
        }
      }

      // This block is technically unreachable.
      if (new_incoming_vals.empty()) {
        llvm::BasicBlock *phi_block = phi->getParent();
        unreachable_blocks.insert(phi_block);
        affected_blocks.insert(phi_block);
        phi->replaceAllUsesWith(llvm::UndefValue::get(phi->getType()));
        phi->dropAllReferences();
        phi->eraseFromParent();

      } else if (new_incoming_vals.size() == 1u) {
        phi->replaceAllUsesWith(new_incoming_vals[0]);
        phi->dropAllReferences();
        phi->eraseFromParent();

      // Create a new PHI node.
      } else {
        auto new_phi = llvm::PHINode::Create(
            phi->getType(), static_cast<unsigned>(new_incoming_vals.size()),
            llvm::Twine::createNull(), phi);
        new_phi->copyMetadata(*phi);

        auto i = 0u;
        for (auto val : new_incoming_vals) {
          new_phi->addIncoming(val, new_incoming_blocks[i++]);
        }

        phi->replaceAllUsesWith(new_phi);
        phi->eraseFromParent();
      }
    }
  }

  return !removed.empty();
}

}  // namespace

// Removes calls to `__remill_error`.
llvm::FunctionPass *CreateRemoveErrorIntrinsics(void) {
  return new RemoveErrorIntrinsics;
}

}  // namespace anvill
