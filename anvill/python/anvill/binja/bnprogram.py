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

import struct

from .typecache import *
from .bnfunction import *
from .bninstruction import *
from .bnvariable import *

from .table import *

from anvill.program import *
from anvill.arch import *
from anvill.os import *
from anvill.imageparser import *
from anvill.util import *
from anvill.type import *


def _is_function_pointer(bn_var):
    var_tinfo = bn_var.type
    if (
        var_tinfo.type_class == bn.TypeClass.PointerTypeClass
        and var_tinfo.element_type.type_class == bn.TypeClass.FunctionTypeClass
    ):
        return True
    return False


class BNProgram(Program):
    def __init__(self, bv: bn.BinaryView, path: str):
        Program.__init__(self, _get_arch(bv), _get_os(bv))
        self._path: Final[str] = path
        self._bv: Final[bn.BinaryView] = bv
        self._type_cache: Final[TypeCache] = TypeCache(self._bv)

        try:
            self._init_func_thunk_ctrl_flow()
        except:
            WARN("Failed to initialize the control flow information for functin thunks")

    @property
    def bv(self):
        return self._bv

    @property
    def type_cache(self):
        return self._type_cache

    def _try_add_symbol(self, ea: int):
        sym: Optional[bn.Symbol] = self._bv.get_symbol_at(ea)
        if not sym:
            return

        self.add_symbol(ea, sym.full_name)

    def get_variable_impl(self, address: int):
        """Given an address, return a `Variable` instance, or
        raise an `InvalidVariableException` exception."""

        # raise exception if the variable has invalid address
        seg = self._bv.get_segment_at(address)
        if seg is None:
            raise InvalidVariableException("Invalid variable address")

        arch = self._arch
        bn_var = self._bv.get_data_var_at(address)

        # `bn_var` can be None if the data variable is not created
        # for it. raise an exception with the address information
        if bn_var is None:
            raise InvalidVariableException(
                "Missing BN data variable at {:x}".format(address)
            )

        self._try_add_symbol(address)
        var_type = self.type_cache.get(bn_var.type)

        # fall back onto an array of bytes type for variables
        # of an unknown (void) type.
        if isinstance(var_type, VoidType):
            var_type = ArrayType()
            var_type.set_num_elements(1)

        return BNVariable(bn_var, arch, address, var_type)

    def _get_function_from_bnvariable(self, address, bn_var):
        """Get the `Function` instance from the data variable of function
        pointer type. Raise an `InvalidFunctionException` exception if
        the data variable is not of function pointer type.
        """
        if bn_var is None:
            return None

        # if the bn_var is an external symbol; discard it It will not get
        # recovered as function or variables
        symbol = self._bv.get_symbol_at(address)
        if symbol != None and symbol.type == bn.SymbolType.ExternalSymbol:
            return None

        if symbol != None and symbol.type != bn.SymbolType.ImportAddressSymbol:
            raise InvalidFunctionException(
                "Not an imported address symbol defined at address {:x}".format(address)
            )

        if not _is_function_pointer(bn_var):
            raise InvalidFunctionException(
                "No function pointer is defined at address {:x}".format(address)
            )

        arch = self._arch
        func_tinfo = bn_var.type.element_type

        # TODO(akshayk): The type information may not have calling convention
        # information. It does not recover the parameters and get the function
        # in such case. A working solution could be handing the default calling
        # convention for each architecture. This is in todo list.
        # cc = func_tinfo.calling_convention
        # if cc is None:
        #     cc = self._bv.arch.calling_conventions[0]

        # calling_conv = CallingConvention(arch, func_tinfo, cc)

        func_type = self.type_cache.get(func_tinfo)

        # Get the start address of function which is assigned to global variable
        is_64bit = self._bv.arch.address_size == 8
        binary_reader = bn.BinaryReader(self._bv, bn.Endianness.LittleEndian)
        binary_reader.seek(address)
        function_start = binary_reader.read64() if is_64bit else binary_reader.read32()

        variable = self._bv.get_data_var_at(function_start)
        func = BNFunction(variable, arch, function_start, [], [], func_type, True, True)
        DEBUG(f"Created a new function from address: [{func.name()}] at 0x{func.address():x} with 0 arguments")
        return func

    def _get_function_parameters(self, bn_func):
        """Get the list of function parameters from the function type. If
        the function type is incorrect or violate the calling conv, return
        the empty list
        """
        param_list = []

        if not isinstance(bn_func, bn.Function):
            return param_list

        index = 0
        calling_conv = CallingConvention(
            self._arch, bn_func, bn_func.calling_convention
        )

        DEBUG(
            f"Looking at function parameters for {bn_func.name} with {len(bn_func.parameter_vars)} parameters."
        )
        try:
            for var in bn_func.parameter_vars:
                source_type = var.source_type
                var_type = var.type

                # Fails to recover var_type for some function which may fail at later stage
                # e.g: int32_t __dlmopen(int32_t arg1, int32_t @ r9, int32_t @ r11)
                if var_type is None:
                    continue

                arg_type = self.type_cache.get(var_type)

                if source_type == bn.VariableSourceType.RegisterVariableSourceType:

                    # For some functions binary ninja identifies the function type incorrectly. The
                    # register allocation in such cases violate calling convention.
                    #
                    # https://github.com/Vector35/binaryninja-api/issues/2399
                    # https://github.com/Vector35/binaryninja-api/issues/2400
                    #
                    # Identify the storage register and discard the parameter variable
                    # if they does not follow calling convention
                    # e.g: int32_t main(int32_t arg1, void* arg2, int128_t arg3 @ q1, int64_t arg4 @ q2)
                    #
                    storage_reg_name = self._bv.arch.get_reg_name(var.storage)
                    if not (
                        storage_reg_name in calling_conv.int_arg_reg
                        or storage_reg_name in calling_conv.float_arg_reg
                    ):
                        raise InvalidParameterException(
                            f"Invalid parameters for function at {bn_func.start:x}: {bn_func.name}. "
                            f"The bad storage register was: {storage_reg_name}."
                        )

                    if isinstance(arg_type, VoidType):
                        raise InvalidParameterException(
                            f"Void type parameter for function at {fn_func.start:x}: {bn_func.name}"
                        )

                    loc = Location()
                    loc.set_register(self._arch.register_name(storage_reg_name))
                    loc.set_type(arg_type)
                    param_list.append(loc)

                elif source_type == bn.VariableSourceType.StackVariableSourceType:
                    loc = Location()
                    loc.set_memory(self._arch.stack_pointer_name(), var.storage)
                    loc.set_type(arg_type)
                    param_list.append(loc)

                index += 1

            return param_list

        except InvalidParameterException as e:
            DEBUG(e)
            return []

    def function_from_addr(self, address):
        bn_func = self._bv.get_function_at(address)
        if not bn_func:
            func_contains = self._bv.get_functions_containing(address)
            if func_contains and len(func_contains):
                bn_func = func_contains[0]

        return bn_func

    def get_function_impl(self, address):
        """Given an architecture and an address, return a `Function` instance or
        raise an `InvalidFunctionException` exception."""
        arch = self._arch

        bn_func = self.function_from_addr(address)

        # A function symbol may be identified as variable by binja.
        if not bn_func:
            # bn_var = self._bv.get_data_var_at(address)
            # if bn_var is not None:
            #    return self._get_function_from_bnvariable(address, bn_var)
            # else:
            raise InvalidFunctionException(
                "No function defined at or containing address {:x}".format(address)
            )

        self._try_add_symbol(address)

        func_type = self.type_cache.get(bn_func.function_type)
        calling_conv = CallingConvention(arch, bn_func, bn_func.calling_convention)
        param_list = self._get_function_parameters(bn_func)

        ret_list = []
        ret_ty = self.type_cache.get(bn_func.return_type)
        if not isinstance(ret_ty, VoidType):
            for reg in calling_conv.return_regs:
                loc = Location()
                loc.set_register(self._arch.register_name(reg))
                loc.set_type(ret_ty)
                ret_list.append(loc)

        has_return_address = self._bv.entry_function != bn_func
        func = BNFunction(bn_func, arch, address, param_list, ret_list, func_type, has_return_address)
        DEBUG(f"Created a new function from address: [{func.name()}] at 0x{func.address():x} with {len(param_list)} arguments")
        return func

    def get_symbols_impl(self, address):
        for s in self._bv.get_symbols(address, 1):
            yield s.name

    @property
    def functions(self):
        for f in self._bv.functions:
            yield f.start

    @property
    def symbols(self):
        for s in self._bv.get_symbols():
            yield (s.address, s.name)

    def _is_callsite(self, func, addr):
        inst_il = func.get_low_level_il_at(addr)
        if is_function_call(self._bv, inst_il):
            return True
        return False

    def _init_func_thunk_ctrl_flow(self):
        """Initializes the control flow redirections and targets
        using function thunks"""

        # We only support the ELF format for now
        if self._bv.view_type != "ELF":
            return

        # List the function thunks first
        input_file_path = self._bv.file.filename
        image_parser = create_elf_image_parser(input_file_path)
        function_thunk_list = image_parser.get_function_thunk_list()

        # Go through each function thunk and add the redirection and targets
        is_32_bit = image_parser.get_image_bitness() == 32

        reader = bn.BinaryReader(self._bv, bn.Endianness.LittleEndian)

        redirected_thunk_list = []
        for function_thunk in function_thunk_list:
            # Read the call destination
            reader.seek(function_thunk.start)
            redirection_dest = reader.read32() if is_32_bit else reader.read64()

            # Get the variable defined at the dest address
            func_location = self._bv.get_data_var_at(function_thunk.start)
            if not func_location:
                DEBUG(
                    f"anvill: No variable defined for {hex(function_thunk.start)}/{function_thunk.name}"
                )
                continue

            # We should only have one caller
            for caller in func_location.code_refs:
                # Get the function containing this address; we need it to determine
                # its start address
                for caller_function in self._bv.get_functions_containing(
                    caller.address
                ):

                    # check if the caller function name is same as the function thunk name and add
                    # redirection if it matches.
                    # TODO: It is possible that the caller function name does not exactly matches the
                    # thunk name. find such cases and add them here
                    #
                    # It is not preferred to have a loose check here. That will lead to adding redirection
                    # for the wrong functions.
                    #
                    if (
                        function_thunk.name == caller_function.name
                        or function_thunk.name == caller_function.name[1:]
                    ):
                        DEBUG(
                            "anvill: Redirecting the user {:x} of thunk {} at {:x} to {:x}".format(
                                caller_function.start,
                                function_thunk.name,
                                function_thunk.start,
                                redirection_dest,
                            )
                        )

                        self.add_control_flow_redirection(
                            caller_function.start, redirection_dest
                        )

                        redirected_thunk_list.append(function_thunk.name)

                    # The imported address symbol can be references from both the thunks
                    # and other functions if it does not uses PLT. Check if the caller
                    # address is one of the call or jump instruction
                    #    e.g:    call [atoi@GOT]
                    #            jmp  [atoi@GOT]
                    #

                    # if the caller address is a call site, set a control flow
                    # target for the address
                    if self._is_callsite(caller_function, caller.address):
                        self.set_control_flow_targets(
                            caller.address, [redirection_dest], True
                        )

                        DEBUG(
                            "anvill: Adding target list {:x} -> [{:x}, complete=True] for {}".format(
                                caller.address, redirection_dest, function_thunk.name
                            )
                        )

                        continue

                    jump_table = get_jump_targets(
                        self._bv, caller.address, function_thunk.start
                    )
                    for jump_addr, targets in jump_table.items():
                        if function_thunk.start in targets:
                            self.set_control_flow_targets(
                                jump_addr, [redirection_dest], True
                            )

                            DEBUG(
                                "anvill: Adding target list {:x} -> [{:x}, complete=True] for {}".format(
                                    jump_addr, redirection_dest, function_thunk.name
                                )
                            )

        # Now check whether we successfully redirected all thunks
        for function_thunk in function_thunk_list:
            if function_thunk.name not in redirected_thunk_list:
                if function_thunk.name == "__libc_start_main":
                    continue

                WARN(
                    f"anvill: Thunk {hex(function_thunk.start)} ({function_thunk.name}) could not be redirected"
                )


def _get_os(bv):
    """OS class that gives access to OS-specific functionality."""
    platform = str(bv.platform)
    if "linux" in platform:
        return LinuxOS()
    elif "mac" in platform:
        return MacOS()
    elif "windows" in platform:
        return WindowsOS()
    else:
        raise UnhandledOSException(
            "Missing operating system object type for OS '{}'".format(platform)
        )


def _get_arch(bv):
    """Arch class that gives access to architecture-specific functionality."""
    name = bv.arch.name
    if name == "x86_64":
        return AMD64Arch()
    elif name == "x86":
        return X86Arch()
    elif name == "aarch64":
        return AArch64Arch()
    elif name == "armv7":
        return AArch32Arch()
    elif name == "thumb2":
        return AArch32Arch()
    else:
        raise UnhandledArchitectureType(
            "Missing architecture object type for architecture '{}'".format(name)
        )
