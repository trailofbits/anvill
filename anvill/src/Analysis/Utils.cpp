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

#include <anvill/ABI.h>
#include <anvill/Analysis/Utils.h>
#include <llvm/ADT/Triple.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Operator.h>

namespace anvill {
namespace {

// Returns `true` if `reg_name` appears to be the name of the stack pointer
// register in the target architecture of `module`.
static bool IsStackPointerRegName(llvm::Module *module,
                                  const std::string &reg_name) {
  llvm::Triple triple(module->getTargetTriple());
  switch (triple.getArch()) {
    case llvm::Triple::ArchType::x86: return reg_name == "esp";
    case llvm::Triple::ArchType::x86_64:
      return reg_name == "rsp" || reg_name == "esp";
    case llvm::Triple::ArchType::aarch64:
      return reg_name == "sp" || reg_name == "xsp" || reg_name == "wsp";
    case llvm::Triple::ArchType::aarch64_32:
    case llvm::Triple::ArchType::arm:
    case llvm::Triple::ArchType::armeb:
      return reg_name == "r13" || reg_name == "sp" || reg_name == "wsp";
    case llvm::Triple::ArchType::sparc:
    case llvm::Triple::ArchType::sparcel:
    case llvm::Triple::ArchType::sparcv9:
      return reg_name == "o6" || reg_name == "sp";
    default: return false;
  }
}

// Returns `true` if `reg_name` appears to be the name of the program counter
// register in the target architecture of `module`.
static bool IsProgramCounterRegName(llvm::Module *module,
                                    const std::string &reg_name) {
  llvm::Triple triple(module->getTargetTriple());
  switch (triple.getArch()) {
    case llvm::Triple::ArchType::x86: return reg_name == "eip";
    case llvm::Triple::ArchType::x86_64:
      return reg_name == "rip" || reg_name == "eip";
    case llvm::Triple::ArchType::aarch64:
      return reg_name == "pc" || reg_name == "wpc";
    case llvm::Triple::ArchType::aarch64_32:
    case llvm::Triple::ArchType::arm:
    case llvm::Triple::ArchType::armeb: return reg_name == "pc";
    case llvm::Triple::ArchType::sparc:
    case llvm::Triple::ArchType::sparcel:
    case llvm::Triple::ArchType::sparcv9:
      return reg_name == "pc" || reg_name == "npc";
    default: return false;
  }
}

// Returns `true` if it looks like we're doing a load of something like
// `__anvill_reg_RSP`, which under certain lifting options, would represent
// an unmodelled dependency on the native stack pointer on entry to a function.
template <typename RegNamePred>
static bool IsLoadOfUnmodelledRegister(llvm::LoadInst *load, RegNamePred pred) {
  if (auto gv =
          llvm::dyn_cast<llvm::GlobalVariable>(load->getPointerOperand())) {
    if (const auto gv_name = gv->getName();
        gv_name.startswith(kUnmodelledRegisterPrefix)) {
      return pred(gv->getParent(),
                  gv_name.substr(kUnmodelledRegisterPrefix.size()).lower());
    }
  }
  return false;
}

// Returns `true` if it looks like we're calling a function that should get
// use the value of the native stack pointer on entry to a function.
//
// NOTE(pag): We're overly defensive here just in case parts of Anvill permit
//            using intrinsics in the future.
static bool IsCallRelatedToStackPointerItrinsic(llvm::CallBase *call) {
  const auto intrinsic_id = call->getIntrinsicID();

  // This is only valid on AArch64.
  if (intrinsic_id == llvm::Intrinsic::sponentry) {
    return true;

  // This intrinsic can be used for getting the address of the stack
  // pointer.
  } else if (intrinsic_id == llvm::Intrinsic::read_register) {
    auto reg_val = call->getArgOperand(0);
    auto reg_tuple_md = llvm::cast<llvm::MDTuple>(
        llvm::cast<llvm::MetadataAsValue>(reg_val)->getMetadata());
    auto reg_name_md = llvm::cast<llvm::MDString>(reg_tuple_md->getOperand(0));
    auto reg_name = reg_name_md->getString().lower();
    return IsStackPointerRegName(call->getModule(), reg_name);

  } else {
    return false;
  }
}

}  // namespace

// Returns `true` if it looks like `val` is derived from a symbolic stack
// pointer representation.
bool IsRelatedToStackPointer(llvm::Module *module, llvm::Value *val) {
  const auto &dl = module->getDataLayout();
  if (auto pti = llvm::dyn_cast<llvm::PtrToIntOperator>(val)) {
    return IsRelatedToStackPointer(module, pti->getOperand(0));

  } else if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(val)) {
    switch (ce->getOpcode()) {
      case llvm::Instruction::IntToPtr:
      case llvm::Instruction::PtrToInt:
      case llvm::Instruction::BitCast:
      case llvm::Instruction::GetElementPtr:
      case llvm::Instruction::Shl:
      case llvm::Instruction::LShr:
      case llvm::Instruction::AShr:
      case llvm::Instruction::UDiv:
      case llvm::Instruction::SDiv:
      case llvm::Instruction::Trunc:
      case llvm::Instruction::SExt:
      case llvm::Instruction::ZExt:
        return IsRelatedToStackPointer(module, ce->getOperand(0));
      case llvm::Instruction::Add:
      case llvm::Instruction::Sub:
      case llvm::Instruction::Mul:
      case llvm::Instruction::And:
      case llvm::Instruction::Or:
      case llvm::Instruction::Xor:
      case llvm::Instruction::ICmp:
        return IsRelatedToStackPointer(module, ce->getOperand(0)) ||
               IsRelatedToStackPointer(module, ce->getOperand(1));
      case llvm::Instruction::Select:
        return IsRelatedToStackPointer(module, ce->getOperand(1)) ||
               IsRelatedToStackPointer(module, ce->getOperand(2));
      case llvm::Instruction::FCmp:
        return IsRelatedToStackPointer(module, ce->getOperand(0)) ||
               IsRelatedToStackPointer(module, ce->getOperand(1)) ||
               IsRelatedToStackPointer(module, ce->getOperand(2));
      default: return false;
    }

  } else if (auto op2 = llvm::dyn_cast<llvm::BinaryOperator>(val)) {
    return IsRelatedToStackPointer(module, op2->getOperand(0)) ||
           IsRelatedToStackPointer(module, op2->getOperand(1));

  } else if (auto op1 = llvm::dyn_cast<llvm::UnaryOperator>(val)) {
    return IsRelatedToStackPointer(module, op1->getOperand(0));

  } else if (auto sel = llvm::dyn_cast<llvm::SelectInst>(val)) {
    return IsRelatedToStackPointer(module, sel->getTrueValue()) ||
           IsRelatedToStackPointer(module, sel->getFalseValue());

  } else if (auto val2 = val->stripPointerCastsAndAliases();
             val2 && val2 != val) {
    return IsRelatedToStackPointer(module, val2);

  } else {
    llvm::APInt ap(dl.getPointerSizeInBits(0), 0);
    if (auto val3 = val->stripAndAccumulateConstantOffsets(dl, ap, true);
        val3 && val3 != val) {
      return IsRelatedToStackPointer(module, val3);
    } else {
      return IsStackPointer(module, val);
    }
  }
}

// Returns `true` if it looks like `val` is the stack counter.
bool IsStackPointer(llvm::Module *module, llvm::Value *val) {
  if (auto gv = llvm::dyn_cast<llvm::GlobalVariable>(val)) {
    return gv->getName() == kSymbolicSPName;

  } else if (auto load = llvm::dyn_cast<llvm::LoadInst>(val)) {
    return IsLoadOfUnmodelledRegister(load, IsStackPointerRegName);

  } else if (auto call = llvm::dyn_cast<llvm::CallBase>(val)) {
    return IsCallRelatedToStackPointerItrinsic(call);

  } else {
    return false;
  }
}

// Returns `true` if it looks like `val` is the program counter.
bool IsProgramCounter(llvm::Module *, llvm::Value *val) {
  if (auto gv = llvm::dyn_cast<llvm::GlobalVariable>(val)) {
    return gv->getName() == kSymbolicPCName;

  } else if (auto load = llvm::dyn_cast<llvm::LoadInst>(val)) {
    return IsLoadOfUnmodelledRegister(load, IsProgramCounterRegName);

  // TODO(pag): Cover arguments to remill three-argument form functions?
  } else {
    return false;
  }
}

static bool IsAcceptableReturnAddressDisplacement(
    llvm::Module *module, llvm::Constant *v) {
  auto ci = llvm::dyn_cast<llvm::ConstantInt>(v);
  if (!ci) {
    return false;
  }

  auto disp = ci->getZExtValue();

  llvm::Triple triple(module->getTargetTriple());
  switch (triple.getArch()) {
    case llvm::Triple::ArchType::sparc:
    case llvm::Triple::ArchType::sparcel:
    case llvm::Triple::ArchType::sparcv9:
      return disp == 0u || disp == 4u || disp == 8u;
    default:
      return disp == 0;
  }
}

// Returns `true` if it looks like `val` is the return address.
bool IsReturnAddress(llvm::Module *module, llvm::Value *val) {
  const auto addressofreturnaddress = [](llvm::CallBase *call) -> bool {
    return call &&
           call->getIntrinsicID() == llvm::Intrinsic::addressofreturnaddress;
  };

  if (auto gv = llvm::dyn_cast<llvm::GlobalVariable>(val)) {
    return gv->getName() == kSymbolicRAName;

  } else if (auto call = llvm::dyn_cast<llvm::CallBase>(val)) {
    if (call->getIntrinsicID() == llvm::Intrinsic::returnaddress) {
      return true;
    } else if (auto func = call->getCalledFunction();
               func && func->getName().startswith("__remill_read_memory_")) {
      return addressofreturnaddress(
          llvm::dyn_cast<llvm::CallBase>(call->getArgOperand(1)));
    } else {
      return false;
    }
  } else if (auto li = llvm::dyn_cast<llvm::LoadInst>(val)) {
    return addressofreturnaddress(
        llvm::dyn_cast<llvm::CallBase>(li->getPointerOperand()));

  } else if (auto pti = llvm::dyn_cast<llvm::PtrToIntOperator>(val)) {
    return IsReturnAddress(module, pti->getOperand(0));

  } else if (auto itp = llvm::dyn_cast<llvm::IntToPtrInst>(val)) {
    return IsReturnAddress(module, itp->getOperand(0));

  } else if (auto bc = llvm::dyn_cast<llvm::BitCastOperator>(val)) {
    return IsReturnAddress(module, bc->getOperand(0));

  } else if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(val)) {
    switch (ce->getOpcode()) {
      case llvm::Instruction::Add: {
        llvm::Constant *o0 = ce->getOperand(0);
        llvm::Constant *o1 = ce->getOperand(1);
        if (IsReturnAddress(module, o0)) {
          return IsAcceptableReturnAddressDisplacement(module, o1);
        } else if (IsReturnAddress(module, o1)) {
          return IsAcceptableReturnAddressDisplacement(module, o0);

        } else {
          return false;
        }
      }

      case llvm::Instruction::IntToPtr:
        return IsReturnAddress(module, ce->getOperand(0));

      default:
        return false;
    }

  } else {
    return false;
  }
}

// Returns `true` if `val` looks like it is backed by a definition, and thus can
// be the aliasee of an `llvm::GlobalAlias`.
bool CanBeAliased(llvm::Value *val) {
  if (!val) {
    return false;
  } else if (auto gv = llvm::dyn_cast<llvm::GlobalVariable>(val)) {
    return !gv->isDeclaration();
  } else if (auto f = llvm::dyn_cast<llvm::Function>(val)) {
    return !f->isDeclaration();
  } else if (auto ga = llvm::dyn_cast<llvm::GlobalAlias>(val)) {
    return CanBeAliased(ga->getAliasee());
  } else if (auto gep = llvm::dyn_cast<llvm::GEPOperator>(val)) {
    return CanBeAliased(gep->getPointerOperand());
  } else if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(val)) {
    switch (ce->getOpcode()) {
      case llvm::Instruction::BitCast:
      case llvm::Instruction::PtrToInt:
      case llvm::Instruction::IntToPtr: return CanBeAliased(ce->getOperand(0));
      default: return false;
    }
  } else {
    return false;
  }
}

}  // namespace anvill
