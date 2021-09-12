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

#include <anvill/Analysis/CrossReferenceResolver.h>
#include <anvill/Lifters/EntityLifter.h>
#include <anvill/Lifters/ValueLifter.h>
#include <anvill/Result.h>

#include <unordered_map>

#include "BaseFunctionPass.h"

namespace anvill {

class TypeProvider;

enum class EntityReferenceErrorCode {
  UnknownError,
};

// Describes an instruction that appears to reference some entity.
struct EntityUse final {
  inline explicit EntityUse(llvm::Use *use_, ResolvedCrossReference xref_)
      : use(use_),
        xref(xref_) {}

  // An operand inside of a particular instruction, where `use->getUser()`
  // is an `llvm::Instruction`, and `use->get()` is a value related to the
  // stack pointer.
  llvm::Use * const use;

  // Resolved cross-reference.
  const ResolvedCrossReference xref;
};

// Contains a list of instruction operand uses that could feasibly be
// entity references.
using EntityUsages = std::vector<EntityUse>;

// This function pass recovers stack information by analyzing the usage
// of the `__anvill_sp` symbol
class RecoverEntityUseInformation final
    : public BaseFunctionPass<RecoverEntityUseInformation> {

  // Entity lifter, used for lifting entities by declaration.
  const EntityLifter entity_lifter;

  // Address lifter, usef for lifting entities by address/type.
  const ValueLifter address_lifter;

  // Used for summarizing/folding values into possible referenced addresses.
  const CrossReferenceResolver xref_resolver;

 public:
  // Creates a new RecoverStackFrameInformation object
  static void Add(llvm::FunctionPassManager &fpm,
                  ITransformationErrorManager &error_manager,
                  const EntityLifter &lifter);

  // Function pass entry point
  llvm::PreservedAnalyses Run(llvm::Function &function);

  // Enumerates some of the possible entity usages that are isolated to
  // specific instruction operand uses.
  EntityUsages EnumeratePossibleEntityUsages(
      llvm::Function &function);

  // Patches the function, replacing the uses known to the entity lifter.
  Result<std::monostate, EntityReferenceErrorCode>
  UpdateFunction(llvm::Function &function, const EntityUsages &uses);

  RecoverEntityUseInformation(ITransformationErrorManager &error_manager,
                              const EntityLifter &lifter);

  virtual ~RecoverEntityUseInformation() override = default;
};

}  // namespace anvill
