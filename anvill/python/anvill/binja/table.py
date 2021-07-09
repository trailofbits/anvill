# Copyright (c) 2020-present Trail of Bits, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import binaryninja as bn
from typing import Optional

from .bninstruction import *

from anvill.util import *

_BADADDR = 0xFFFFFFFFFFFFFFFF


def _evaluate_destination_expression(bv, inst, dest):
    """The function extract possible target ea from the destination
    expression of the jump or tail calls.
    """
    target_eas = []
    if is_constant_pointer(bv, dest) or is_import_address(bv, dest):
        const_ea = dest.constant
        target_eas.append(const_ea)

    elif is_memory_inst(bv, dest) or is_unimplemented_mem(bv, dest):
        possible_value = dest.value
        if is_constant_pointer(bv, possible_value):
            const_ea = possible_value.constant
            target_eas.append(const_ea)

    elif is_register_inst(bv, dest) or is_push_inst(bv, inst):
        if isinstance(dest.src, bn.lowlevelil.ILRegister):
            possible_pointer = inst.get_reg_value(dest.src.name)

            if (
                possible_pointer.type
                == bn.function.RegisterValueType.ConstantPointerValue
                or possible_pointer.type
                == bn.function.RegisterValueType.ExternalPointerValue
                or possible_pointer.type
                == bn.function.RegisterValueType.ImportedAddressValue
            ):
                target_eas.append(possible_pointer.value)

    else:
        DEBUG(f"Unhandled destination expressions inst {inst} dest {repr(dest)}")

    return target_eas


def _extract_targets_from_tailcall(bv, inst):
    """Get the target ea for the instructions with tail calls"""
    if not (
        isinstance(inst, bn.LowLevelILInstruction)
        or isinstance(inst, bn.MediumLevelILInstruction)
    ):
        return

    target_eas = []

    if not is_function_tailcall(bv, inst):
        return target_eas

    target_eas.extend(_evaluate_destination_expression(bv, inst, inst.dest))

    # if instruction is not mlil; call the function with mlil
    if not isinstance(inst, bn.MediumLevelILInstruction):
        if inst.mlil:
            target_eas.extend(_extract_targets_from_tailcall(bv, inst.mlil))

    return target_eas


def _extract_targets_from_jump(bv, inst):
    """Get the target ea from the jump instructions"""
    if not (
        isinstance(inst, bn.LowLevelILInstruction)
        or isinstance(inst, bn.MediumLevelILInstruction)
    ):
        return

    target_eas = []

    if not is_jump(bv, inst):
        return target_eas

    target_eas.extend(_evaluate_destination_expression(bv, inst, inst.dest))

    # if the instruction is not mlil, call the function with MLIL. It gets
    # the target ea if they are not recovered from llil
    if not isinstance(inst, bn.MediumLevelILInstruction):
        if inst.mlil:
            target_eas.extend(_extract_targets_from_jump(bv, inst.mlil))

    return target_eas


def _extract_targets_from_jump_to(bv, inst):
    """If the instruction is jump to, it is a jump table
    constructs and contains the list of possible targets
    """

    if not (
        isinstance(inst, bn.LowLevelILInstruction)
        or isinstance(inst, bn.MediumLevelILInstruction)
    ):
        return

    target_eas = []
    possible_targets = inst.targets
    for block in bv.get_basic_blocks_at(inst.address):
        for target in possible_targets:
            target_eas.append(target)

    return target_eas


def _find_jumps_near(bv, addr):
    """Find indirect jump instructions near instruction at
    address `addr`. Return empty list if not found
    """
    candidates = []
    for block in bv.get_basic_blocks_at(addr):
        jump_addr = addr

        while jump_addr < block.end:
            info = bv.arch.get_instruction_info(bv.read(jump_addr, 16), jump_addr)

            # Add a check if info is None; go to the next address
            if info is None:
                DEBUG(f"Could not get instruction at jump destination: {jump_addr:x}")
                break

            # check if the instruction has branches
            if len(info.branches) != 0:
                candidates.append(jump_addr)
                break

            jump_addr += info.length

        if jump_addr >= block.end:
            continue

    return candidates


def is_jump_addr(bv, addr):
    info = bv.arch.get_instruction_info(bv.read(addr, 16), addr)
    return info and len(info.branches) != 0


def _get_jump_targets_unresolved(bv, jump_ea, entry_ea=_BADADDR):
    """The jump target branches can be unresolved. The function
    goes through the jump instruction and identify the possible
    targets
    """
    target_eas = []
    for function in bv.get_functions_containing(jump_ea):
        insn_il = function.get_low_level_il_at(jump_ea)
        if is_function_tailcall(bv, insn_il):
            target_eas = _extract_targets_from_tailcall(bv, insn_il)

        elif is_jump(bv, insn_il):
            target_eas = _extract_targets_from_jump(bv, insn_il)

        elif is_jump_to(bv, insn_il):
            target_eas = _extract_targets_from_jump_to(bv, insn_il)

    return [ea for ea in target_eas if ea != 0]


def get_jump_targets(bv, inst_ea, entry_ea=_BADADDR):
    """Get jump targets for the instruction at address `addr`. If
    the instruction is not a jump instruction; find all jumps
    near the instruction and get their targets.
    """

    jump_targets = dict()
    if not is_jump_addr(bv, inst_ea):
        jump_eas = _find_jumps_near(bv, inst_ea)
    else:
        jump_eas = [inst_ea]

    for jump_ea in jump_eas:
        branch_targets = []

        # if the targets of the branch is unresolved, it could be a jump table
        # entry; A tail call can also be identified as unresolved branch. Identify
        # the tail call target in such case
        info = bv.arch.get_instruction_info(bv.read(jump_ea, 16), jump_ea)
        if info is None:
            DEBUG(f"Could not get instruction at jump destination: {jump_ea:x}")
            continue
        
        # TODO(AK): Handle other type of branches
        for branch in info.branches:
            if branch.type in (
                bn.BranchType.TrueBranch,
                bn.BranchType.FalseBranch,
                bn.BranchType.UnconditionalBranch,
            ):
                branch_targets.append(branch.target)

            elif branch.type in (
                bn.BranchType.IndirectBranch,
                bn.BranchType.UnresolvedBranch,
            ):
                branch_targets = _get_jump_targets_unresolved(bv, jump_ea, entry_ea)

        jump_targets[jump_ea] = branch_targets

    return jump_targets
