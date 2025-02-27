/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/CrossReferenceResolver.h>
#include <anvill/Declarations.h>
#include <anvill/Lifters.h>
#include <anvill/Passes/ConvertAddressesToEntityUses.h>
#include <anvill/Providers.h>
#include <anvill/Utils.h>
#include <glog/logging.h>
#include <llvm/IR/Constant.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

#include <unordered_set>

#include "Utils.h"

namespace anvill {
namespace {

// Get the annotation for the program counter `pc`.
static llvm::MDNode *GetPCAnnotation(llvm::Module *module, uint64_t pc) {
  auto &dl = module->getDataLayout();
  auto &context = module->getContext();
  auto address_type =
      llvm::Type::getIntNTy(context, dl.getPointerSizeInBits(0));
  auto pc_val = llvm::ConstantInt::get(address_type, pc);
  auto pc_md = llvm::ValueAsMetadata::get(pc_val);
  return llvm::MDNode::get(context, pc_md);
}

}  // namespace

llvm::PreservedAnalyses
ConvertAddressesToEntityUses::run(llvm::Function &function,
                                  llvm::FunctionAnalysisManager &fam) {
  if (function.isDeclaration()) {
    return llvm::PreservedAnalyses::all();
  }

  EntityUsages uses = EnumeratePossibleEntityUsages(function);
  if (uses.empty()) {
    return llvm::PreservedAnalyses::all();
  }

  std::unordered_set<llvm::Instruction *> to_erase;

  for (EntityUse xref_use : uses) {
    const auto val = xref_use.use->get();
    const auto val_type = val->getType();
    const auto ra = xref_use.xref;

    const auto user_inst =
        llvm::dyn_cast<llvm::Instruction>(xref_use.use->getUser());
    llvm::IRBuilder<> ir(user_inst);
    llvm::Value *entity = nullptr;

    llvm::Type *pointee_type = nullptr;
    unsigned address_space = 0u;

    entity = xref_resolver.EntityAtAddress(ra.u.address, pointee_type,
                                           address_space);

    if (!entity) {
      continue;
    }

    entity = entity->stripPointerCasts();

    // Apply the PC metadata annotation to all resolved addresses.
    if (pc_metadata_id) {
      if (auto obj = llvm::dyn_cast<llvm::GlobalObject>(entity)) {
        auto module = function.getParent();
        obj->setMetadata(*pc_metadata_id,
                         GetPCAnnotation(module, ra.u.address));
      }
    }

    auto ent_type = llvm::dyn_cast<llvm::PointerType>(entity->getType());
    CHECK_NOTNULL(ent_type);

    if (auto phi = llvm::dyn_cast<llvm::PHINode>(user_inst)) {
      auto pred_block = phi->getIncomingBlock(*(xref_use.use));
      llvm::IRBuilder<> ir(pred_block->getTerminator());
      xref_use.use->set(AdaptToType(ir, entity, val_type));
    } else {
      llvm::IRBuilder<> ir(user_inst);
      xref_use.use->set(AdaptToType(ir, entity, val_type));
    }

    if (auto val_inst = llvm::dyn_cast<llvm::Instruction>(val)) {
      to_erase.insert(val_inst);
    }
  }

  for (auto val_inst : to_erase) {
    if (val_inst->use_empty()) {
      val_inst->eraseFromParent();
    }
  }

  return llvm::PreservedAnalyses::none();
}

llvm::StringRef ConvertAddressesToEntityUses::name(void) {
  return "ConvertAddressesToEntityUses";
}

EntityUsages ConvertAddressesToEntityUses::EnumeratePossibleEntityUsages(
    llvm::Function &function) {

  EntityUsages output;
  if (function.isDeclaration()) {
    return output;
  }

  CrossReferenceFolder xref_folder(xref_resolver,
                                   function.getParent()->getDataLayout());

  //  const auto arch = this->entity_lifter.Options().arch;
  //  const auto mem_ptr_type = arch->MemoryPointerType();
  //  const auto state_ptr_type = arch->StatePointerType();

  for (auto &basic_block : function) {
    for (auto &instr : basic_block) {
      for (auto i = 0u, num_ops = instr.getNumOperands(); i < num_ops; ++i) {
        auto &use = instr.getOperandUse(i);
        auto val = use.get();
        if (!val) {
          continue;  // Can happen as a result of `dropAllReferences`.
        }

        //        // If we see something related to Remill's `Memory *` or `State *`
        //        // then ignore those as being possible cross-references.
        //        const auto val_type = val->getType();
        //        if (val_type == mem_ptr_type || val_type == state_ptr_type) {
        //          continue;
        //        }

        if (auto ra = xref_folder.TryResolveReferenceWithClearedCache(val);
            ra.is_valid && !ra.references_return_address &&
            !ra.references_stack_pointer) {

          if (ra.references_entity ||  // Related to an existing lifted entity.
              ra.references_global_value ||  // Related to a global var/func.
              ra.references_program_counter) {  // Related to `__anvill_pc`.
            output.emplace_back(&use, ra);
          }
        }
      }
    }
  }

  return output;
}

ConvertAddressesToEntityUses::ConvertAddressesToEntityUses(
    const CrossReferenceResolver &xref_resolver_,
    std::optional<unsigned> pc_metadata_id_)
    : xref_resolver(xref_resolver_),
      pc_metadata_id(std::move(pc_metadata_id_)) {}

// Anvill-lifted code is full of references to constant expressions related
// to `__anvill_pc`. These constant expressions exist to "taint" values as
// being possibly related to the program counter, and thus likely being
// pointers.
//
// This goal of this pass is to opportunistically identify uses of values
// that are related to the program counter, and likely to be references to
// other entitities. We say opportunistic because that pass is not guaranteed
// to replace all such references, and will in fact leave references around
// for later passes to benefit from.
void AddConvertAddressesToEntityUses(llvm::FunctionPassManager &fpm,
                                     const CrossReferenceResolver &resolver,
                                     std::optional<unsigned> pc_annot_id) {
  fpm.addPass(ConvertAddressesToEntityUses(resolver, std::move(pc_annot_id)));
}

}  // namespace anvill
