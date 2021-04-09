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


import ida_funcs
import ida_typeinf
import ida_nalt
import ida_idp
import idc
import ida_bytes
import ida_frame
import ida_auto
import ida_ida
import ida_name


from .utils import *
from .idafunction import *
from .idavariable import *


from anvill.program import *
from anvill.type import *
from anvill.imageparser import *


TYPE_CONTEXT_NESTED = 0
TYPE_CONTEXT_GLOBAL_VAR = 1
TYPE_CONTEXT_FUNCTION = 2
TYPE_CONTEXT_PARAMETER = 3
TYPE_CONTEXT_RETURN = 4

_FLOAT_SIZES = (2, 4, 8, 10, 12, 16)


class IDAProgram(Program):
    def __init__(self, arch, os):
        # Wait until IDA has finished analysis before we proceed, otherwise
        # we will end up missing code, data and cross references
        ida_auto.auto_wait()

        super(IDAProgram, self).__init__(arch, os)
        self._init_ctrl_flow_redirections()

    def get_variable_impl(self, address):
        """Given an address, return a `Variable` instance, or
        raise an `InvalidVariableException` exception."""
        arch = self._arch

        seg_ref = [None]
        address, backup_var_type = _invent_var_type(address, seg_ref)
        if not backup_var_type:
            raise InvalidVariableException(
                "No variable defined at or containing address {:x}".format(address)
            )

        assert not isinstance(backup_var_type, VoidType)

        tif = ida_typeinf.tinfo_t()
        if not ida_nalt.get_tinfo(tif, address):
            if ida_typeinf.GUESS_FUNC_OK != ida_typeinf.guess_tinfo(tif, address):
                tif = backup_var_type

        # Try to handle a variable type, otherwise make it big and empty.
        try:
            var_type = _get_type(tif, TYPE_CONTEXT_GLOBAL_VAR)
            if isinstance(var_type, VoidType):
                var_type = backup_var_type

        except UnhandledTypeException as e:
            print(
                "Could not assign type to variable at address {:x}: {}".format(
                    address, str(e)
                )
            )
            var_type = backup_var_type

        assert not isinstance(var_type, VoidType)
        assert not isinstance(var_type, FunctionType)

        self.add_symbol(address, _variable_name(address))
        var = IDAVariable(
            arch, address, var_type, find_segment_containing_ea(address, seg_ref)
        )
        return var

    def get_function_impl(self, address):
        """Given an address, return a `Function` instance or
        raise an `InvalidFunctionException` exception."""
        arch = self._arch
        os = self._os

        pfn = ida_funcs.get_func(address)
        if not pfn:
            pfn = ida_funcs.get_prev_func(address)

        seg_ref = [None]
        seg = find_segment_containing_ea(address, seg_ref)

        # Check this function.
        if not pfn or not seg:
            raise InvalidFunctionException(
                "No function defined at or containing address {:x}".format(address)
            )

        elif (
            not ida_funcs.func_contains(pfn, address)
            and not _is_extern_seg(seg)
            and not is_imported_table_seg(seg)
        ):
            raise InvalidFunctionException(
                "No function defined at or containing address {:x}".format(address)
            )

        # Reset to the start of the function, and get the type of the function.
        address = pfn.start_ea

        tif = ida_typeinf.tinfo_t()
        if not ida_nalt.get_tinfo(tif, address):
            if ida_typeinf.GUESS_FUNC_OK != ida_typeinf.guess_tinfo(tif, address):
                raise InvalidFunctionException(
                    "Can't guess type information for function at address {:x}".format(
                        address
                    )
                )

        if not tif.is_func():
            raise InvalidFunctionException(
                "Type information at address {:x} is not a function: {}".format(
                    address, tif.dstr()
                )
            )

        ftd = ida_typeinf.func_type_data_t()
        if not tif.get_func_details(ftd):
            raise InvalidFunctionException(
                "Could not get function details for function at address {:x}".format(
                    address
                )
            )

        # Make sure we can handle the basic signature of the function. This might
        # not be the final signature that we go with, but it's a good way to make
        # sure we can handle the relevant types.
        try:
            func_type = _get_type(tif, TYPE_CONTEXT_FUNCTION)
        except UnhandledTypeException as e:
            raise InvalidFunctionException(
                "Could not assign type to function at address {:x}: {}".format(
                    address, str(e)
                )
            )

        # Get the calling convention. The CC might override `is_variadic`, e.g. how
        # old style C functions declared as `foo()` actually imply `foo(...)`.
        cc, is_variadic = _get_calling_convention(arch, os, ftd)
        if is_variadic:
            func_type.set_is_variadic()

        # Go look into each of the parameters and their types. Each parameter may
        # refer to multiple locations, so we want to split each of those locations
        # into unique
        i = 0
        max_i = ftd.size()
        param_list = []
        while i < max_i:
            funcarg = ftd[i]
            i += 1

            arg_type = _get_type(funcarg.type, TYPE_CONTEXT_PARAMETER)
            arg_type_str = arg_type.serialize(arch, {})

            j = len(param_list)
            _expand_locations(arch, pfn, arg_type, funcarg.argloc, param_list)

            # If we have a parameter name, then give a name to each of the expanded
            # locations associated with this parameter.
            if funcarg.name:
                if (j + 1) == len(param_list):
                    param_list[-1].set_name(funcarg.name)
                else:
                    k = j
                    while k < len(param_list):
                        param_list[-1].set_name("{}_{}".format(funcarg.name, k - j))
                        k += 1

        # Build up the list of return values.
        ret_list = []
        ret_type = _get_type(ftd.rettype, TYPE_CONTEXT_RETURN)
        if not isinstance(ret_type, VoidType):
            _expand_locations(arch, pfn, ret_type, ftd.retloc, ret_list)

        func = IDAFunction(
            arch, address, param_list, ret_list, pfn, ftd.is_noret(), func_type, cc
        )
        self.add_symbol(address, _function_name(address))
        return func

    def _init_ctrl_flow_redirections(self):
        """Initializes the control flow redirections using function thunks"""

        # List the function thunks first
        input_file_path = ida_nalt.get_input_file_path()

        inf = ida_idaapi.get_inf_structure()
        if inf.filetype == ida_ida.f_ELF:
            image_parser = create_elf_image_parser(input_file_path)

        elif inf.filetype == ida_ida.f_PE:
            image_parser = create_pe_image_parser(input_file_path)

        else:
            return

        function_thunk_list = image_parser.get_function_thunk_list()

        # Go through each function thunk, and look at its cross references; there
        # should always be only one user, which is the wrapper around the imported
        # function
        #
        # Note that the __libc_start_main thunk does not need redirection since
        # it's called directly without any wrapper function from the module entry
        # point
        is_32_bit = image_parser.get_image_bitness() == 32

        for function_thunk in function_thunk_list:
            if function_thunk.name == "__libc_start_main":
                continue

            thunk_va = ida_nalt.get_imagebase() + function_thunk.start

            redirection_dest: int = 0
            caller_address: int = 0

            if ida_bytes.is_loaded(thunk_va):
                redirection_dest = (
                    ida_bytes.get_wide_dword(thunk_va)
                    if is_32_bit
                    else ida_bytes.get_qword(thunk_va)
                )

                caller_address = ida_xref.get_first_cref_to(redirection_dest)

            else:
                redirection_dest = thunk_va
                caller_address = ida_xref.get_first_dref_to(redirection_dest)

            if caller_address == ida_idaapi.BADADDR:
                print(
                    "Control flow redirection failed for {} at {:x} => {:x}".format(
                        function_thunk.name,
                        function_thunk.start,
                        thunk_va,
                    )
                )

                continue

            redirection_source = idc.get_func_attr(caller_address, idc.FUNCATTR_START)

            print(
                "anvill: Redirecting the user {:x} of thunk {} at rva {:x} to {:x}".format(
                    redirection_source,
                    function_thunk.name,
                    function_thunk.start,
                    redirection_dest,
                )
            )

            self.add_control_flow_redirection(redirection_source, redirection_dest)


def _convert_ida_type(tinfo, cache, depth, context):
    """Convert an IDA `tinfo_t` instance into a `Type` instance."""
    assert isinstance(tinfo, ida_typeinf.tinfo_t)

    if 0 < depth:
        context = TYPE_CONTEXT_NESTED

    tinfo_str = str(tinfo)
    if tinfo_str in cache and context in (TYPE_CONTEXT_NESTED, TYPE_CONTEXT_FUNCTION):
        return cache[tinfo_str]

    # Void type.
    elif tinfo.empty() or tinfo.is_void():
        return VoidType()

    # Pointer, array, or function.
    elif tinfo.is_paf():
        if tinfo.is_ptr():
            ret = PointerType()
            cache[tinfo_str] = ret
            ret.set_element_type(
                _convert_ida_type(tinfo.get_pointed_object(), cache, depth + 1, context)
            )
            return ret

        elif tinfo.is_func():
            ret = FunctionType()
            cache[tinfo_str] = ret
            ret.set_return_type(
                _convert_ida_type(tinfo.get_rettype(), cache, depth + 1, context)
            )
            i = 0
            max_i = tinfo.get_nargs()
            while i < max_i:
                ret.add_parameter_type(
                    _convert_ida_type(tinfo.get_nth_arg(i), cache, depth + 1, context)
                )
                i += 1

            if tinfo.is_vararg_cc():
                ret.set_is_variadic()

            if tinfo.is_purging_cc():
                ret.set_num_bytes_popped_off_stack(tinfo.calc_purged_bytes())

            if TYPE_CONTEXT_NESTED == context or TYPE_CONTEXT_FUNCTION == context:
                return ret

            func_ptr = PointerType()
            func_ptr.set_element_type(ret)
            return func_ptr

        elif tinfo.is_array():
            num_elems = tinfo.get_array_nelems()
            if 0 == num_elems:
                # Strings in IDA will have a type of `char[]`.
                if TYPE_CONTEXT_GLOBAL_VAR == context:
                    return _convert_ida_type(
                        tinfo.get_array_element(), cache, depth + 1, context
                    )
                else:
                    ret = PointerType()
                    cache[tinfo_str] = ret
                    ret.set_element_type(
                        _convert_ida_type(
                            tinfo.get_array_element(), cache, depth + 1, context
                        )
                    )
                    return ret
            else:
                ret = ArrayType()
                cache[tinfo_str] = ret
                ret.set_element_type(
                    _convert_ida_type(
                        tinfo.get_array_element(), cache, depth + 1, context
                    )
                )
                ret.set_num_elements(num_elems)
                return ret

        else:
            raise UnhandledTypeException(
                "Unhandled pointer, array, or function type: {}".format(tinfo.dstr()),
                tinfo,
            )

    # Vector types.
    elif tinfo.is_sse_type():
        ret = VectorType()
        cache[tinfo_str] = ret
        size = tinfo.get_size()

        # TODO(pag): Do better than this.
        ret.set_element_type(IntegerType(1, False))
        ret.set_num_elements(size)

        return ret

    # Structure, union, or enumerator.
    elif tinfo.is_sue():
        if tinfo.is_udt():  # Structure or union type.
            ret = tinfo.is_struct() and StructureType() or UnionType()
            cache[tinfo_str] = ret
            i = 0
            max_i = tinfo.get_udt_nmembers()
            while i < max_i:
                udt = ida_typeinf.udt_member_t()
                udt.offset = i
                if not tinfo.find_udt_member(udt, ida_typeinf.STRMEM_INDEX):
                    break
                # TODO(pag): bitfields
                # TODO(pag): padding
                ret.add_element_type(
                    _convert_ida_type(udt.type, cache, depth + 1, context)
                )
                i += 1
            return ret

        elif tinfo.is_enum():
            ret = EnumType()
            cache[tinfo_str] = ret
            base_type = ida_typeinf.tinfo_t(tinfo.get_enum_base_type())
            ret.set_underlying_type(_convert_ida_type(base_type, cache, depth, context))
            return ret

        else:
            raise UnhandledTypeException(
                "Unhandled struct, union, or enum type: {}".format(tinfo.dstr()), tinfo
            )

    # Boolean type.
    elif tinfo.is_bool():
        return BoolType()

    # Integer type.
    elif tinfo.is_integral():
        return IntegerType(tinfo.get_unpadded_size(), tinfo.is_signed())

    # Floating point.
    elif tinfo.is_floating():
        size = tinfo.get_unpadded_size()
        if size in _FLOAT_SIZES:
            return FloatingPointType(size)
        elif tinfo.is_ldouble():
            return FloatingPointType(10)
        elif tinfo.is_double():
            return FloatingPointType(8)
        elif tinfo.is_float():
            return FloatingPointType(4)
        else:
            raise UnhandledTypeException(
                "Unhandled floating point type: {}".format(tinfo.dstr()), tinfo
            )

    elif tinfo.is_complex():
        raise UnhandledTypeException(
            "Complex numbers are not yet handled: {}".format(tinfo.dstr()), tinfo
        )

    # Type alias/reference.
    #
    # NOTE(pag): We return the underlying type because it may be void.
    elif tinfo.is_typeref():
        ret = TypedefType()
        cache[tinfo_str] = ret
        utype = _convert_ida_type(
            ida_typeinf.tinfo_t(tinfo.get_realtype(True)), cache, depth, context
        )
        ret.set_underlying_type(utype)
        cache[tinfo_str] = utype
        return utype

    else:
        raise UnhandledTypeException("Unhandled type: {}".format(tinfo.dstr()), tinfo)


def _get_type(ty, context):
    """Type class that gives access to type sizes, printings, etc."""

    if isinstance(ty, Type):
        return ty

    elif isinstance(ty, Function):
        return ty.type()

    elif isinstance(ty, Location):
        return ty.type()

    elif isinstance(ty, ida_typeinf.tinfo_t):
        return _convert_ida_type(ty, {}, 0, context)

    tif = ida_typeinf.tinfo_t()
    try:
        if not ida_nalt.get_tinfo(tif, ty):
            ida_typeinf.guess_tinfo(tif, ty)
    except:
        pass

    if not tif.empty():
        return _convert_ida_type(tif, {}, 0, context)

    if not ty:
        return VoidType()

    raise UnhandledTypeException("Unrecognized type passed to `Type`.", ty)


def _get_address_sized_reg(arch, reg_name):
    """Given the regiseter name `reg_name`, find the name of the register in the
    same family whose size is the pointer size of this architecture."""

    try:
        family = arch.register_family(reg_name)
        addr_size = arch.pointer_size()
        for f_reg_name, f_reg_offset, f_reg_size in family:
            if 0 == f_reg_offset and addr_size == f_reg_size:
                return f_reg_name
    except:
        pass
    return arch.register_name(reg_name)


def _expand_locations(arch, pfn, ty, argloc, out_locs):
    """Expand the locations referred to by `argloc` into a list of `Location`s
    in `out_locs`."""

    reg_names = ida_idp.ph_get_regnames()
    where = argloc.atype()

    if where == ida_typeinf.ALOC_STACK:
        sp_adjust_retaddr = int(
            ida_frame.frame_off_args(pfn) - ida_frame.frame_off_retaddr(pfn)
        )
        loc = Location()
        loc.set_memory(arch.stack_pointer_name(), argloc.stkoff() + sp_adjust_retaddr)
        loc.set_type(ty)
        out_locs.append(loc)

    # Distributed across two or more locations.
    elif where == ida_typeinf.ALOC_DIST:
        for part in argloc.scattered():
            part_ty = ty.extract(arch, part.off, part.size)
            _expand_locations(arch, pfn, part_ty, part, out_locs)

    # Located in a single register, possibly in a small part of the register
    # itself.
    elif where == ida_typeinf.ALOC_REG1:
        ty_size = ty.size(arch)
        reg_name = reg_names[argloc.reg1()].upper()
        try:
            reg_offset = argloc.regoff()
            family = arch.register_family(reg_name)

            # Try to guess the right name for the register based on the size of the
            # type that it will contain. For example, IDA will tell us register `ax`
            # is used, not specify if it's `al`, `ah`, `eax`, or `rax`.
            #
            # NOTE: The registers in the family tuple are sorted in descending
            #       order of size.
            found = False
            for f_reg_name, f_reg_offset, f_reg_size in family:
                if f_reg_offset != reg_offset:
                    continue

                if ty_size == f_reg_size:
                    found = True
                    reg_name = f_reg_name
                    break

            if not found:
                raise Exception()

        except:
            reg_name = (
                ida_idp.get_reg_name(argloc.reg1(), ty_size) or reg_name
            ).upper()

        loc = Location()
        loc.set_register(arch.register_name(reg_name))
        loc.set_type(ty)
        out_locs.append(loc)

    # Located in a pair of registers.
    elif where == ida_typeinf.ALOC_REG2:
        ty_size = ty.size(arch)
        reg_name1 = reg_names[argloc.reg1()].upper()
        reg_name2 = reg_names[argloc.reg2()].upper()
        ty1 = ty.extract(arch, 0, ty_size / 2)
        ty2 = ty.extract(arch, ty_size / 2, ty_size / 2)

        try:
            found = False
            family1 = arch.register_family(reg_name1)
            family2 = arch.register_family(reg_name2)

            # Try to guess which registers IDA actually meant. For example, for
            # an `EDX:EAX` return value, our `ty_size` will be 8 bytes, but IDA will
            # report the registers as `ax` and `dx` (due to those being the names in
            # `ph_get_regnames`). So, we have to scan through the associated family
            # and try to see if we can guess the right version of those registers.
            for r1_info, r2_info in itertools.product(family1, family2):
                f_reg_name1, f_reg_offset1, f_reg_size1 = r1_info
                f_reg_name2, f_reg_offset2, f_reg_size2 = r2_info

                if f_reg_offset1 or f_reg_offset2:
                    continue

                if ty_size == (f_reg_size1 + f_reg_size2):
                    found = True
                    reg_name1 = f_reg_name1
                    reg_name2 = f_reg_name2

                    ty1 = ty.extract(arch, 0, f_reg_size1)
                    ty2 = ty.extract(arch, f_reg_size1, f_reg_size2)
                    break

            if not found:
                raise Exception()

        except Exception as e:
            reg_name1 = (
                ida_idp.get_reg_name(argloc.reg1(), ty_size) or reg_name1
            ).upper()
            reg_name2 = (
                ida_idp.get_reg_name(argloc.reg2(), ty_size) or reg_name2
            ).upper()

        loc1 = Location()
        loc1.set_register(arch.register_name(reg_name1))
        loc1.set_type(ty1)
        out_locs.append(loc1)

        loc2 = Location()
        loc2.set_register(arch.register_name(reg_name2))
        loc2.set_type(ty2)
        out_locs.append(loc2)

    # Memory location computed as value in a register, plus an offset.
    #
    # TODO(pag): How does this work if the register itself is not
    #            treated as an argument?
    elif where == ida_typeinf.ALOC_RREL:
        rrel = argloc.get_rrel()
        loc = Location()
        loc.set_memory(
            _get_address_sized_reg(arch, reg_names[rrel.reg].upper()), rrel.off
        )
        loc.set_type(ty)
        out_locs.append(loc)

    # Global variable with a fixed address. We can represent this
    # as computing a PC-relative memory address.
    elif where == ida_typeinf.ALOC_STATIC:
        loc = Location()
        loc.set_memory(arch.program_counter_name(), argloc.get_ea() - ea)
        loc.set_type(ty)
        out_locs.append(loc)

    # Unsupported.
    else:
        raise InvalidLocationException(
            "Unsupported location {} with type {}".format(
                str(argloc), ty.serialize(arch, {})
            )
        )


def _is_extern_seg(seg):
    """Returns `True` if `seg` refers to a segment with external variable or
    function declarations."""
    if not seg:
        return False

    seg_type = idc.get_segm_attr(seg.start_ea, idc.SEGATTR_TYPE)
    return seg_type == idc.SEG_XTRN


def _variable_name(ea):
    """Return the name of a variable."""
    try:
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.has_name(flags):
            return ida_name.get_ea_name(ea)
    except:
        pass
    return ""


def _get_calling_convention(arch, os, ftd):
    is_variadic = ftd.is_vararg_cc()
    arch_name = arch.name()
    default_cc = os.default_calling_convention(arch)
    if arch_name == "x86":

        if (ftd.cc & ida_typeinf.CM_CC_STDCALL) == ida_typeinf.CM_CC_STDCALL:
            return 64, is_variadic
        elif (ftd.cc & ida_typeinf.CM_CC_CDECL) == ida_typeinf.CM_CC_CDECL:
            return 0, is_variadic
        elif (ftd.cc & ida_typeinf.CM_CC_ELLIPSIS) == ida_typeinf.CM_CC_ELLIPSIS:
            return 0, True
        elif (ftd.cc & ida_typeinf.CM_CC_THISCALL) == ida_typeinf.CM_CC_THISCALL:
            return 70, is_variadic
        else:
            return default_cc, is_variadic

    # NOTE(pag): Most x86 calling conventions are ignored in 64-bit.
    elif arch_name == "amd64":
        if (ftd.cc & ida_typeinf.CM_CC_STDCALL) == ida_typeinf.CM_CC_STDCALL:
            return default_cc, is_variadic
        elif (ftd.cc & ida_typeinf.CM_CC_CDECL) == ida_typeinf.CM_CC_CDECL:
            return default_cc, is_variadic
        elif (ftd.cc & ida_typeinf.CM_CC_ELLIPSIS) == ida_typeinf.CM_CC_ELLIPSIS:
            return default_cc, True
        elif (ftd.cc & ida_typeinf.CM_CC_THISCALL) == ida_typeinf.CM_CC_THISCALL:
            return 70, is_variadic
        else:
            return default_cc, is_variadic

    elif arch_name == "aarch32":
        # check for _cdecl calling convention else fallback to default cc
        if (ftd.cc & ida_typeinf.CM_CC_CDECL) == ida_typeinf.CM_CC_CDECL:
            return 48, is_variadic
        else:
            return default_cc, is_variadic

    # Unknown, just assume the default C calling convention.
    else:
        return default_cc, is_variadic


def _function_name(ea):
    """Try to get the name of a function."""
    try:
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.has_name(flags):
            return ida_funcs.get_func_name(ea)
    except:
        pass
    return "sub_{:x}".format(ea)


def _invent_var_type(ea, seg_ref, min_size=1):
    """Try to invent a variable type. This will basically be an array of bytes
    that spans what we need. We will, however, try to be slightly smarter and
    look for cross-references in the range, and when possible, use their types."""
    seg = find_segment_containing_ea(ea, seg_ref)
    if not seg:
        return ea, None

    head_ea = ida_bytes.get_item_head(ea)
    if head_ea < ea:
        head_seg = find_segment_containing_ea(head_ea, seg_ref)
        if head_seg != seg:
            return ea, None
        return _invent_var_type(head_ea, seg_ref, ea - head_ea)

    min_size = max(min_size, ida_bytes.get_item_size(ea))
    next_ea = ida_bytes.next_head(ea + 1, seg.end_ea)
    next_seg = find_segment_containing_ea(next_ea, seg_ref)

    arr = ArrayType()
    arr.set_element_type(IntegerType(1, False))

    if not next_seg or next_seg != seg:
        arr.set_num_elements(min_size)
        return ea, arr

    min_size = min(min_size, next_ea - ea)

    # TODO(pag): Go and do a better job, e.g. find pointers inside of the global.
    # i = 0
    # while i < min_size:
    #   for ref_ea in xref_generator(ea + i, seg_ref):
    #     break
    #   i += 1

    arr.set_num_elements(min_size)
    return ea, arr
