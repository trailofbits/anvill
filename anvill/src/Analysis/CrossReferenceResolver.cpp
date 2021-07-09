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

#include <glog/logging.h>

#include <anvill/ABI.h>
#include <anvill/Analysis/CrossReferenceResolver.h>
#include <anvill/Analysis/Utils.h>
#include <anvill/Lifters/EntityLifter.h>
#include <anvill/Lifters/Options.h>

#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <remill/BC/Util.h>

#include <unordered_map>

namespace anvill {
namespace {

using AddressResolverFuncType =
    std::function<std::optional<uint64_t>(llvm::Constant *)>;

using EntityResolverFuncType = std::function<llvm::Constant *(uint64_t)>;

// Convert an unsigned value `val` of size `size` bits into a signed `int64_t`.
static int64_t Signed(uint64_t val, uint64_t size) {
  switch (size) {
    case 1:
      if (val & 1) {
        return -1;
      } else {
        return 0;
      }
    case 8: return static_cast<int8_t>(val);
    case 16: return static_cast<int16_t>(val);
    case 32: return static_cast<int8_t>(val);
    case 64: return static_cast<int64_t>(val);
    default:
      const uint64_t m = 1ull << (size - 1ull);
      return static_cast<int64_t>(((val ^ m) - m));
  }
}

}  // namespace

class CrossReferenceResolverImpl {
 public:
  CrossReferenceResolverImpl(const llvm::DataLayout &dl_,
                             AddressResolverFuncType address_of_entity_,
                             EntityResolverFuncType entity_at_address_)
      : dl(dl_),
        address_of_entity(address_of_entity_),
        entity_at_address(entity_at_address_) {}

  ResolvedCrossReference ResolveInstruction(llvm::Instruction *inst_val);
  ResolvedCrossReference ResolveConstant(llvm::Constant *const_val);
  ResolvedCrossReference ResolveGlobalValue(llvm::GlobalValue *const_val);
  ResolvedCrossReference ResolveConstantExpr(llvm::ConstantExpr *const_val);

  // Try to resolve `val` as a cross-reference.
  ResolvedCrossReference ResolveCall(llvm::CallInst *val);

  // Try to resolve `val` as a cross-reference.
  ResolvedCrossReference ResolveValue(llvm::Value *val);

  // Merge and saturate the flags of `lhs` and `rhs`. It is acceptable for
  // `lhs` or `rhs` to promote pointerness.
  template <typename Op>
  ResolvedCrossReference Merge(ResolvedCrossReference lhs,
                               ResolvedCrossReference rhs, Op &&merge_vals);

  // Merge and saturate the flags of `lhs` and `rhs`. It is acceptable for
  // `lhs` to promote pointerness, but not `rhs`.
  template <typename Op>
  ResolvedCrossReference MergeLeft(ResolvedCrossReference lhs,
                                   ResolvedCrossReference rhs, Op &&merge_vals);

  // Returns the "magic" value that represents the return address.
  uint64_t MagicReturnAddressValue(void) const;

#define NO_WRAP(val, size) val
#define SIGNED_WRAP(val, size) Signed(val, size)
#define MAKE_BINOP_FOLDER(name, op, merge, wrap, allow_rhs_zero) \
  ResolvedCrossReference Fold##name(ResolvedCrossReference lhs_xr, \
                                    ResolvedCrossReference rhs_xr, \
                                    uint64_t mask, uint64_t size) { \
    if (allow_rhs_zero || rhs_xr.u.address & mask) { \
      return merge(lhs_xr, rhs_xr, [=](uint64_t lhs, uint64_t rhs) { \
        return static_cast<uint64_t>((wrap(lhs, size) op wrap(rhs, size))) & \
               mask; \
      }); \
    } else { \
      return {}; \
    } \
  }

  MAKE_BINOP_FOLDER(Add, +, Merge, SIGNED_WRAP, true)
  MAKE_BINOP_FOLDER(Sub, -, Merge, SIGNED_WRAP, true)
  MAKE_BINOP_FOLDER(Mul, *, Merge, SIGNED_WRAP, true)
  MAKE_BINOP_FOLDER(And, &, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(Or, |, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(Xor, ^, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(Shl, <<, MergeLeft, NO_WRAP, true)
  MAKE_BINOP_FOLDER(LShr, >>, MergeLeft, NO_WRAP, true)
  MAKE_BINOP_FOLDER(AShr, >>, MergeLeft, SIGNED_WRAP, true)
  MAKE_BINOP_FOLDER(UDiv, /, MergeLeft, NO_WRAP, false)
  MAKE_BINOP_FOLDER(URem, %, MergeLeft, NO_WRAP, false)
  MAKE_BINOP_FOLDER(SDiv, /, MergeLeft, SIGNED_WRAP, false)
  MAKE_BINOP_FOLDER(SRem, %, MergeLeft, SIGNED_WRAP, false)
  MAKE_BINOP_FOLDER(ICmpEq, ==, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(ICmpNe, !=, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(ICmpUgt, >, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(ICmpUge, >=, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(ICmpUlt, <, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(ICmpUle, <, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(ICmpSgt, >, Merge, SIGNED_WRAP, false)
  MAKE_BINOP_FOLDER(ICmpSge, >=, Merge, SIGNED_WRAP, false)
  MAKE_BINOP_FOLDER(ICmpSlt, <, Merge, SIGNED_WRAP, false)
  MAKE_BINOP_FOLDER(ICmpSle, <=, Merge, SIGNED_WRAP, false)

#undef MAKE_BINOP_FOLDER
#undef NO_WRAP
#undef SIGNED_WRAP

  ResolvedCrossReference FoldICmp(ResolvedCrossReference lhs_xr,
                                  ResolvedCrossReference rhs_xr, uint64_t mask,
                                  uint64_t size, unsigned pred) {
    switch (pred) {
      case llvm::CmpInst::ICMP_EQ:
        return FoldICmpEq(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_NE:
        return FoldICmpNe(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_UGT:
        return FoldICmpUgt(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_UGE:
        return FoldICmpUge(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_ULT:
        return FoldICmpUlt(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_ULE:
        return FoldICmpUle(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_SGT:
        return FoldICmpSgt(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_SGE:
        return FoldICmpSge(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_SLT:
        return FoldICmpSlt(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_SLE:
        return FoldICmpSle(lhs_xr, rhs_xr, mask, size);
      default: return {};
    }
  }

  const llvm::DataLayout dl;

  // Entity address resolver for figuring out the address of globals/functions.
  const AddressResolverFuncType address_of_entity;

  // Entity address resolver for figuring out the globals/functions associated
  // with addresses.
  const EntityResolverFuncType entity_at_address;

  // Cache of resolved values.
  std::unordered_map<llvm::Value *, ResolvedCrossReference> xref_cache;
};


// Merge and saturate the flags of `lhs` and `rhs`. It is acceptable for
// `lhs` or `rhs` to promote pointerness.
template <typename Op>
ResolvedCrossReference
CrossReferenceResolverImpl::Merge(ResolvedCrossReference lhs,
                                  ResolvedCrossReference rhs, Op &&merge_vals) {
  ResolvedCrossReference xr = {};
  xr.u.address = merge_vals(lhs.u.address, rhs.u.address);
  xr.is_valid = lhs.is_valid & rhs.is_valid;
  xr.references_entity = lhs.references_entity | rhs.references_entity;
  xr.references_global_value =
      lhs.references_global_value | rhs.references_global_value;
  xr.references_program_counter =
      lhs.references_program_counter | rhs.references_program_counter;
  xr.references_return_address =
      lhs.references_return_address | rhs.references_return_address;
  xr.references_stack_pointer =
      lhs.references_stack_pointer | rhs.references_stack_pointer;
  xr.hinted_value_type = nullptr;
  xr.displacement_from_hinted_value_type = 0;

  if (lhs.hinted_value_type && rhs.hinted_value_type) {

    // Not clear how to combine, so drop the type info. E.g. we could be
    // dealing with a `ptrdiff_t` logically, i.e. the distance between
    // two pointers.

    // TODO(pag): Think more about the difference between two entities
    //            case. It might be that we don't want to actually fold
    //            this type of symbolic expression down.

  } else if (lhs.hinted_value_type) {
    const auto diff = xr.u.displacement - lhs.u.displacement;
    xr.hinted_value_type = lhs.hinted_value_type;
    xr.displacement_from_hinted_value_type =
        lhs.displacement_from_hinted_value_type + diff;

  } else if (rhs.hinted_value_type) {
    const auto diff = xr.u.displacement - rhs.u.displacement;
    xr.hinted_value_type = rhs.hinted_value_type;
    xr.displacement_from_hinted_value_type =
        rhs.displacement_from_hinted_value_type + diff;
  }

  return xr;
}

// Merge and pick the flags of `lhs` and `rhs`. It is acceptable for
// `lhs` to promote pointerness, but not `rhs`.
template <typename Op>
ResolvedCrossReference CrossReferenceResolverImpl::MergeLeft(
    ResolvedCrossReference lhs, ResolvedCrossReference rhs, Op &&merge_vals) {
  ResolvedCrossReference xr = {};
  xr.u.address = merge_vals(lhs.u.address, rhs.u.address);
  xr.is_valid = lhs.is_valid & rhs.is_valid;
  xr.references_entity = lhs.references_entity;
  xr.references_global_value = lhs.references_global_value;
  xr.references_program_counter = lhs.references_program_counter;
  xr.references_return_address = lhs.references_return_address;
  xr.references_stack_pointer = lhs.references_stack_pointer;
  xr.hinted_value_type = lhs.hinted_value_type;
  xr.displacement_from_hinted_value_type +=
      static_cast<int64_t>(xr.u.address - lhs.u.address);
  return xr;
}

ResolvedCrossReference
CrossReferenceResolverImpl::ResolveInstruction(llvm::Instruction *inst_val) {

  auto opnd_type = inst_val->getOperand(0)->getType();
  uint64_t size = opnd_type->getPrimitiveSizeInBits();
  // update size if the operand is of pointer type
  if (opnd_type->isPointerTy()) {
    size = dl.getPointerSizeInBits(0);
  }

  const uint64_t mask = size < 64 ? (1ull << size) - 1ull : ~0ull;
  uint64_t out_size = inst_val->getType()->getPrimitiveSizeInBits();
  if (inst_val->getType()->isPointerTy()) {
    out_size = dl.getPointerSizeInBits(0);
  }
  const uint64_t out_mask = out_size < 64 ? (1ull << out_size) - 1ull : ~0ull;

  switch (inst_val->getOpcode()) {
#define FOLD_CASE(name) \
  case llvm::Instruction::name: { \
    auto xr = Fold##name(ResolveValue(inst_val->getOperand(0)), \
                         ResolveValue(inst_val->getOperand(1)), mask, size); \
    xr.size = static_cast<unsigned>(out_size); \
    return xr; \
  }

    FOLD_CASE(Add)
    FOLD_CASE(Sub)
    FOLD_CASE(Mul)
    FOLD_CASE(And)
    FOLD_CASE(Or)
    FOLD_CASE(Xor)
    FOLD_CASE(Shl)
    FOLD_CASE(LShr)
    FOLD_CASE(AShr)
    FOLD_CASE(SDiv)
    FOLD_CASE(UDiv)
    FOLD_CASE(SRem)
    FOLD_CASE(URem)

#undef FOLD_CASE

    case llvm::Instruction::ZExt: {
      auto xr = ResolveValue(inst_val->getOperand(0));
      xr.u.address &= mask;
      xr.size = static_cast<unsigned>(out_size);
      return xr;
    }

    case llvm::Instruction::SExt: {
      auto xr = ResolveValue(inst_val->getOperand(0));
      xr.u.displacement = Signed(xr.u.address, size);
      xr.u.address &= out_mask;
      xr.size = static_cast<unsigned>(out_size);
      return xr;
    }

    case llvm::Instruction::Trunc: {
      auto xr = ResolveValue(inst_val->getOperand(0));
      xr.u.address &= out_mask;
      xr.size = static_cast<unsigned>(out_size);
      return xr;
    }

    case llvm::Instruction::IntToPtr: {
      auto xr = ResolveValue(inst_val->getOperand(0));
      xr.size = static_cast<unsigned>(out_size);
      if (auto ptr_type = llvm::cast<llvm::PointerType>(inst_val->getType());
          !xr.displacement_from_hinted_value_type) {
        xr.hinted_value_type = ptr_type->getElementType();
      }
      return xr;
    }

    case llvm::Instruction::PtrToInt:{
       auto xr = ResolveValue(inst_val->getOperand(0));
       xr.size = static_cast<unsigned>(out_size);
       return xr;
    }

    case llvm::Instruction::BitCast: {
      auto xr = ResolveValue(inst_val->getOperand(0));
      xr.size = static_cast<unsigned>(out_size);
      if (auto ptr_type =
              llvm::dyn_cast<llvm::PointerType>(inst_val->getType());
          ptr_type && !xr.displacement_from_hinted_value_type) {
        xr.hinted_value_type = ptr_type->getElementType();
      }
      return xr;
    }

    case llvm::Instruction::Call:{
      auto xr = ResolveCall(llvm::dyn_cast<llvm::CallInst>(inst_val));
      xr.size = static_cast<unsigned>(out_size);
      return xr;
    }

    default: return {};
  }
}

// Try to resolve a constant to a cross-reference.
ResolvedCrossReference
CrossReferenceResolverImpl::ResolveConstant(llvm::Constant *const_val) {

  auto it = xref_cache.find(const_val);
  if (it != xref_cache.end()) {
    return it->second;
  }

  auto &xr = xref_cache[const_val];

  if (auto gv = llvm::dyn_cast<llvm::GlobalValue>(const_val)) {
    xr = ResolveGlobalValue(gv);
    xr.size = dl.getPointerSizeInBits(0);

  } else if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(const_val)) {
    xr = ResolveConstantExpr(ce);

  } else if (auto ci = llvm::dyn_cast<llvm::ConstantInt>(const_val)) {
    const llvm::APInt &val = ci->getValue();
    xr.size = val.getBitWidth();
    xr.is_valid = false;

    if (val.isNegative()) {
      if (val.getMinSignedBits() <= 64) {
        xr.u.address = static_cast<uint64_t>(val.getSExtValue());
        xr.is_valid = true;
      }
    } else if (val.getActiveBits() <= 64) {
      xr.u.address = val.getZExtValue();
      xr.is_valid = true;
    }

  } else if (auto cpn = llvm::dyn_cast<llvm::ConstantPointerNull>(const_val)) {
    xr.hinted_value_type = cpn->getType()->getElementType();
    xr.is_valid = true;
    xr.size =  dl.getPointerSizeInBits(0);

  } else {
    xr.is_valid = false;
  }

  return xr;
}

ResolvedCrossReference
CrossReferenceResolverImpl::ResolveGlobalValue(llvm::GlobalValue *gv) {

  ResolvedCrossReference xr = {};

  auto module = gv->getParent();
  if (auto var = llvm::dyn_cast<llvm::GlobalVariable>(gv)) {
    if (IsProgramCounter(module, gv)) {
      xr.references_program_counter = true;
      xr.is_valid = true;
      return xr;

    } else if (IsStackPointer(module, gv)) {
      xr.references_stack_pointer = true;
      xr.is_valid = true;
      return xr;

    } else if (IsReturnAddress(module, gv)) {
      xr.u.address = MagicReturnAddressValue();
      xr.references_return_address = true;
      xr.is_valid = true;
      return xr;
    }
  }

  xr.references_global_value = true;

  if (auto maybe_addr = address_of_entity(gv); maybe_addr) {
    xr.u.address = *maybe_addr;
    xr.references_entity = true;
    xr.is_valid = true;
  }

  if (auto [base, offset] = remill::StripAndAccumulateConstantOffsets(dl, gv);
      base) {
    xr.hinted_value_type = base->getType()->getPointerElementType();
    xr.displacement_from_hinted_value_type = offset;

  } else if (!llvm::isa<llvm::Function>(gv)) {
    xr.hinted_value_type = gv->getValueType();
    xr.displacement_from_hinted_value_type = 0;
  }

  return xr;
}

ResolvedCrossReference
CrossReferenceResolverImpl::ResolveConstantExpr(llvm::ConstantExpr *ce) {

  if (auto maybe_addr = address_of_entity(ce); maybe_addr) {
    ResolvedCrossReference xr;
    xr.u.address = *maybe_addr;
    xr.size = dl.getPointerSizeInBits(0);
    xr.references_entity = true;
    xr.is_valid = true;
    if (auto ptr_ty = llvm::dyn_cast<llvm::PointerType>(ce->getType())) {
      xr.hinted_value_type = ptr_ty->getElementType();
    }
    return xr;
  }

  const auto ptr_size = dl.getPointerSizeInBits(0);
  auto opnd_type = ce->getOperand(0)->getType();
  uint64_t size = opnd_type->getPrimitiveSizeInBits();
  // update size if operand is pointer type
  if (opnd_type->isPointerTy()) {
    size = ptr_size;
  }
  const uint64_t mask = size < 64 ? (1ull << size) - 1ull : ~0ull;
  uint64_t out_size = ce->getType()->getPrimitiveSizeInBits();
  // update size if constant expr is pointer type
  if (ce->getType()->isPointerTy()) {
    out_size = ptr_size;
  }
  const uint64_t out_mask = out_size < 64 ? (1ull << out_size) - 1ull : ~0ull;

  switch (ce->getOpcode()) {
    default: break;

#define FOLD_CASE(name) \
  case llvm::Instruction::name: { \
    auto xr = Fold##name(ResolveConstant(ce->getOperand(0)), \
                         ResolveConstant(ce->getOperand(1)), mask, size); \
    xr.size = static_cast<unsigned>(out_size); \
		return xr; \
  }

      FOLD_CASE(Add)
      FOLD_CASE(Sub)
      FOLD_CASE(Mul)
      FOLD_CASE(And)
      FOLD_CASE(Or)
      FOLD_CASE(Xor)
      FOLD_CASE(Shl)
      FOLD_CASE(LShr)
      FOLD_CASE(AShr)
      FOLD_CASE(SDiv)
      FOLD_CASE(UDiv)
      FOLD_CASE(SRem)
      FOLD_CASE(URem)

#undef FOLD_CASE

    case llvm::Instruction::ZExt: {
      auto xr = ResolveConstant(ce->getOperand(0));
      xr.u.address &= mask;
      xr.size = static_cast<unsigned>(out_size);
      return xr;
    }

    case llvm::Instruction::SExt: {
      auto xr = ResolveConstant(ce->getOperand(0));
      xr.u.displacement = Signed(xr.u.address, size);
      xr.u.address &= out_mask;
      xr.size = static_cast<unsigned>(out_size);
      return xr;
    }

    case llvm::Instruction::Trunc: {
      auto xr = ResolveConstant(ce->getOperand(0));
      xr.u.address &= out_mask;
      xr.size = static_cast<unsigned>(out_size);
      return xr;
    }

    case llvm::Instruction::IntToPtr: {
      auto xr = ResolveConstant(ce->getOperand(0));
      xr.size = static_cast<unsigned>(out_size);
      if (auto ptr_type = llvm::cast<llvm::PointerType>(ce->getType());
          !xr.displacement_from_hinted_value_type) {
        xr.hinted_value_type = ptr_type->getElementType();
      }
      return xr;
    }

    case llvm::Instruction::PtrToInt: {
      auto xr = ResolveConstant(ce->getOperand(0));
      xr.size = static_cast<unsigned>(out_size);
      return xr;
    }

    case llvm::Instruction::BitCast: {
      auto xr = ResolveConstant(ce->getOperand(0));
      xr.size = static_cast<unsigned>(out_size);
      if (auto ptr_type = llvm::dyn_cast<llvm::PointerType>(ce->getType());
          ptr_type && !xr.displacement_from_hinted_value_type) {
        xr.hinted_value_type = ptr_type->getElementType();
      }
      return xr;
    }

    case llvm::Instruction::ICmp: {
      auto xr = FoldICmp(ResolveConstant(ce->getOperand(0)),
                      ResolveConstant(ce->getOperand(1)), mask, size,
                      ce->getPredicate());
      xr.size = static_cast<unsigned>(out_size);
      return xr;
    }

    case llvm::Instruction::GetElementPtr: {
      auto base = ResolveConstant(ce->getOperand(0));

      // In the event that an index is non-constant, we'll try to also resolve
      // it using our value resolver.
      auto visit = [=](llvm::Value &val, llvm::APInt &ap) -> bool {
        if (const auto index_xr = ResolveValue(&val); index_xr.is_valid) {
          ap += static_cast<uint64_t>(Signed(index_xr.u.address, ptr_size));
          return true;
        } else {
          return false;
        }
      };

      const auto gep = llvm::dyn_cast<llvm::GEPOperator>(ce);
      llvm::APInt ap(ptr_size, 0);
      if (!gep->accumulateConstantOffset(dl, ap, visit)) {
        base.is_valid = false;
        return base;
      }

      const auto disp = Signed(ap.getZExtValue(), ptr_size);
      base.u.address += static_cast<uint64_t>(disp);
      base.size = static_cast<unsigned>(out_size);
      base.displacement_from_hinted_value_type += disp;
      return base;
    }

    // TODO(pag): Consider doing merge on both sides.
    // TODO(pag): What happens if there's a `trunc` on a pointer and that is
    //            the condition?
    case llvm::Instruction::Select: {
      auto cond = ResolveConstant(ce->getOperand(0));
      ResolvedCrossReference selected_val = {};
      if (cond.u.address) {
        selected_val = ResolveConstant(ce->getOperand(1));
      } else {
        selected_val = ResolveConstant(ce->getOperand(2));
      }
      selected_val.size = static_cast<unsigned>(out_size);
      selected_val.is_valid &= cond.is_valid;
      return selected_val;
    }
  }

  return {};
}

// Try to resolve `val` as a cross-reference.
ResolvedCrossReference
CrossReferenceResolverImpl::ResolveCall(llvm::CallInst *call) {
  switch (call->getIntrinsicID()) {
    case llvm::Intrinsic::ctlz: {
      auto xr = ResolveValue(call->getArgOperand(0));
      xr.u.address = __builtin_clzl(xr.u.address);
      xr.size = call->getType()->getPrimitiveSizeInBits();
      return xr;
    }
    case llvm::Intrinsic::cttz: {
      auto xr = ResolveValue(call->getArgOperand(0));
      xr.u.address = __builtin_ctzl(xr.u.address);
      xr.size = call->getType()->getPrimitiveSizeInBits();
      return xr;
    }
    case llvm::Intrinsic::ctpop: {
      auto xr = ResolveValue(call->getArgOperand(0));
      xr.u.address = __builtin_popcountl(xr.u.address);
      xr.size = call->getType()->getPrimitiveSizeInBits();
      return xr;
    }

    // Not an intrinsic.
    case 0: break;

    // Unsupported intrinsic.
    default: return {};
  }

  // Looks like a call through a type hint function.
  if (auto func = call->getCalledFunction();
      func && func->getName().startswith(kTypeHintFunctionPrefix)) {
    auto xr = ResolveValue(call->getArgOperand(0));
    xr.hinted_value_type = func->getReturnType()->getPointerElementType();
    xr.displacement_from_hinted_value_type = 0;
    xr.size = dl.getPointerSizeInBits(0);
    return xr;

  // Not a call through a type hint, ignore it.
  } else {
    return {};
  }
}

// Try to resolve `val` as a cross-reference.
ResolvedCrossReference
CrossReferenceResolverImpl::ResolveValue(llvm::Value *val) {
  if (auto const_val = llvm::dyn_cast<llvm::Constant>(val)) {
    return ResolveConstant(const_val);

  } else if (auto inst_val = llvm::dyn_cast<llvm::Instruction>(val)) {
    return ResolveInstruction(inst_val);

  } else {
    return {};
  }
}

// Returns the "magic" value that represents the return address.
uint64_t CrossReferenceResolverImpl::MagicReturnAddressValue(void) const {
  uint64_t addr = 0x4141414141414141ull;
  switch (dl.getPointerSizeInBits(0)) {
    case 16: return static_cast<uint16_t>(addr); break;
    case 32: return static_cast<uint32_t>(addr); break;
    default: return addr;
  }
}

CrossReferenceResolver::~CrossReferenceResolver(void) {}

// The primary way of using a cross-reference resolver is with an entity
// lifter that can resolve global references on our behalf.
CrossReferenceResolver::CrossReferenceResolver(const EntityLifter &lifter)
    : impl(std::make_shared<CrossReferenceResolverImpl>(
          lifter.Options().module->getDataLayout(),
          [=](llvm::Constant *entity) {
            return lifter.AddressOfEntity(entity);
          },
          [=](uint64_t addr) -> llvm::Constant * {
            llvm::Constant *ret = nullptr;
            return ret;
          })) {}

// In the absence of an entity lifter, we need a DataLayout to determine
// offsets, etc.
CrossReferenceResolver::CrossReferenceResolver(const llvm::DataLayout &dl)
    : impl(std::make_shared<CrossReferenceResolverImpl>(
          dl, [](llvm::Constant *) { return std::nullopt; },
          [](uint64_t) -> llvm::Constant * { return nullptr; })) {}

// Clear the internal cache.
void CrossReferenceResolver::ClearCache(void) const {
  impl->xref_cache.clear();
}

// Try to resolve `val` as a cross-reference.
ResolvedCrossReference
CrossReferenceResolver::TryResolveReference(llvm::Value *val) const {
  return impl->ResolveValue(val);
}

// Returns the "magic" value that represents the return address.
uint64_t CrossReferenceResolver::MagicReturnAddressValue(void) const {
  return impl->MagicReturnAddressValue();
}

std::int64_t
ResolvedCrossReference::Displacement(const llvm::DataLayout &dl) const {
  std::int64_t displacement{};

  CHECK_NE(size, 0) << "Reference size should not be zero!";

  switch (std::min(size, dl.getPointerSizeInBits(0))) {
    case 8:  displacement = static_cast<std::int8_t> (u.displacement); break;
    case 16: displacement = static_cast<std::int16_t>(u.displacement); break;
    case 32: displacement = static_cast<std::int32_t>(u.displacement); break;
    case 64: displacement = u.displacement; break;
  }

  return displacement;
}

}  // namespace anvill
