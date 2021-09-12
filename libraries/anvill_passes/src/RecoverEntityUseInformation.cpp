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

#include "RecoverEntityUseInformation.h"

#include <anvill/Decl.h>
#include <anvill/Lifters/Options.h>
#include <anvill/Lifters/ValueLifter.h>
#include <anvill/Providers/TypeProvider.h>
#include <llvm/IR/Constant.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

#include "Utils.h"

namespace anvill {

void RecoverEntityUseInformation::Add(
    llvm::FunctionPassManager &fpm, ITransformationErrorManager &error_manager,
    const EntityLifter &lifter) {
  fpm.addPass(RecoverEntityUseInformation(error_manager, lifter));
}

llvm::PreservedAnalyses
RecoverEntityUseInformation::Run(llvm::Function &function) {
  if (function.isDeclaration()) {
    return llvm::PreservedAnalyses::all();
  }

  auto uses = EnumeratePossibleEntityUsages(function);
  if (uses.empty()) {
    return llvm::PreservedAnalyses::all();
  }

  // It is now time to patch the function. This method will take the stack
  // analysis and use it to generate a stack frame type and update all the
  // instructions
  auto update_func_res = UpdateFunction(function, uses);
  if (!update_func_res.Succeeded()) {
    EmitError(
        SeverityType::Fatal, update_func_res.Error(),
        "Function transformation has failed and there was a failure recovering "
        "an entity reference");

    return llvm::PreservedAnalyses::all();
  }

  return llvm::PreservedAnalyses::none();
}

EntityUsages RecoverEntityUseInformation::EnumeratePossibleEntityUsages(
    llvm::Function &function) {

  EntityUsages output;
  if (function.isDeclaration()) {
    return output;
  }

  const auto arch = this->entity_lifter.Options().arch;
  const auto mem_ptr_type = arch->MemoryPointerType();
  const auto state_ptr_type = arch->StatePointerType();

  for (auto &basic_block : function) {
    for (auto &instr : basic_block) {
      for (auto i = 0u, num_ops = instr.getNumOperands(); i < num_ops; ++i) {
        auto &use = instr.getOperandUse(i);
        auto val = use.get();

        // If we see something related to Remill's `Memory *` or `State *` then
        // ignore those as being possible cross-references.
        const auto val_type = val->getType();
        if (val_type == mem_ptr_type || val_type == state_ptr_type) {
          continue;
        }

        if (auto ra = xref_resolver.TryResolveReference(val);
            ra.is_valid && !ra.references_return_address &&
            !ra.references_stack_pointer) {

          if (ra.hinted_value_type ||  // Looked like a pointer.
              ra.references_entity ||  // Related to an existing lifted entity.
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

// Patches the function, replacing the uses known to the entity entity_lifter.
Result<std::monostate, EntityReferenceErrorCode>
RecoverEntityUseInformation::UpdateFunction(llvm::Function &function,
                                            const EntityUsages &uses) {

  ValueLifter value_lifter(entity_lifter);
  auto &type_provider = entity_lifter.TypeProvider();
  const auto module = function.getParent();
  const auto &dl = module->getDataLayout();
  auto &context = module->getContext();

  std::unordered_set<llvm::Instruction *> to_erase;

  for (auto xref_use : uses) {
    const auto val = xref_use.use->get();
    const auto val_type = val->getType();
    const auto ra = xref_use.xref;

    const auto user_inst =
        llvm::dyn_cast<llvm::Instruction>(xref_use.use->getUser());
    llvm::IRBuilder<> ir(user_inst);
    llvm::PointerType *inferred_type = nullptr;
    llvm::Value *entity = nullptr;

    // As a first pass, take the inferred type of this entity from the cross-
    // reference info.
    if (xref_use.xref.hinted_value_type &&
        !xref_use.xref.displacement_from_hinted_value_type) {
      inferred_type = xref_use.xref.hinted_value_type->getPointerTo(0);

      // TODO(pag): If we have an `hinted_value_type`, and a non-zero
      //            displacement then figure out what the value type is, if
      //            we're in-bounds of the type.
    }

    // Failing this, check if the value we're looking at is a pointer, and use
    // that type.
    if (!inferred_type) {
      inferred_type = llvm::dyn_cast<llvm::PointerType>(val_type);
    }

    // We have inferred a pointer type from the usage site or from the value.
    if (inferred_type) {

      // NOTE(pag): `address_lifter.Lift` will return `nullptr` for
      //            unresolved references in order to satisfy the request.
      entity = address_lifter.Lift(ra.u.address, inferred_type);

    // We have not inferred information about this, time to go find it.
    } else {

      bool is_var = false;
      uint64_t var_address = 0;

      // Try to look it up as a function.
      if (auto maybe_func_decl = type_provider.TryGetFunctionType(ra.u.address);
          maybe_func_decl) {
        entity = entity_lifter.DeclareEntity(*maybe_func_decl);

      // Try to look it up as a variable.
      } else if (auto maybe_var_decl =
                     type_provider.TryGetVariableType(ra.u.address, dl)) {
        is_var = true;
        var_address = maybe_var_decl->address;
        entity = entity_lifter.LiftEntity(*maybe_var_decl);

      // Try to see if it's one past the end of a known entity.
      } else if (auto maybe_prev_var_decl =
                     type_provider.TryGetVariableType(ra.u.address - 1u, dl);
                 maybe_prev_var_decl && ra.u.address) {

        is_var = true;
        var_address = maybe_prev_var_decl->address;
        entity = entity_lifter.LiftEntity(*maybe_prev_var_decl);
      }
      CopyMetadataTo(val, entity);

      // TODO(pag): Can we do better than an `i8 *`?
      if (entity && is_var && var_address < ra.u.address) {
        auto i8_ptr_ty = llvm::Type::getInt8PtrTy(context);
        entity = remill::BuildPointerToOffset(
            ir, entity, ra.u.address - var_address, i8_ptr_ty);
        CopyMetadataTo(val, entity);
      }
    }

    if (entity) {
      if (val_type->isIntegerTy()) {
        const auto intptr_ty = llvm::Type::getIntNTy(
            context, dl.getPointerSizeInBits(
                         entity->getType()->getPointerAddressSpace()));
        entity = ir.CreatePtrToInt(entity, intptr_ty);
        CopyMetadataTo(val, entity);
        entity = ir.CreateZExtOrTrunc(entity, val->getType());
        CopyMetadataTo(val, entity);
        xref_use.use->set(entity);

      } else if (val_type->isPointerTy()) {
        entity = ir.CreatePointerBitCastOrAddrSpaceCast(entity, val_type);
        CopyMetadataTo(val, entity);
        xref_use.use->set(entity);

      } else {

        // TODO(pag): Report error/warning?
      }

      if (auto val_inst = llvm::dyn_cast<llvm::Instruction>(val);
          val_inst && val_inst->use_empty()) {
        to_erase.insert(val_inst);
      }

    } else {

      // TODO(pag): Report warning/informational?
    }
  }

  for (auto val_inst : to_erase) {
    val_inst->eraseFromParent();
  }

  return std::monostate();
}

RecoverEntityUseInformation::RecoverEntityUseInformation(
    ITransformationErrorManager &error_manager, const EntityLifter &lifter_)
    : BaseFunctionPass(error_manager),
      entity_lifter(lifter_),
      address_lifter(lifter_),
      xref_resolver(lifter_) {}

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
void AddRecoverEntityUseInformation(llvm::FunctionPassManager &fpm,
                                    ITransformationErrorManager &error_manager,
                                    const EntityLifter &lifter) {
  RecoverEntityUseInformation::Add(fpm, error_manager, lifter);
}

}  // namespace anvill
