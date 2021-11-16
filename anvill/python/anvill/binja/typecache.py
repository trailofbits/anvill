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
from typing import Dict

import binaryninja as bn

from .callingconvention import *

from anvill.type import *
from anvill.function import *
from anvill.util import *

CacheKey = str


def _cache_key(tinfo: bn.types.Type) -> CacheKey:
    """ Convert bn Type instance to cache key"""
    return str(tinfo)


class TypeCache:
    """The class provides API to recursively visit the binja types and convert
    them to the anvill `Type` instance. It maintains a cache of visited binja
    types to reduce lookup time.
    """

    _bv: bn.BinaryView
    _cache: Dict[CacheKey, bn.types.Type]

    # list of unhandled type classes which should log error
    _err_type_class = {
        bn.TypeClass.VarArgsTypeClass: "VarArgsTypeClass",
        bn.TypeClass.ValueTypeClass: "ValueTypeClass",
        bn.TypeClass.WideCharTypeClass: "WideCharTypeClass",
    }

    def __init__(self, bv):
        self._bv = bv
        self._cache = dict()

    def _convert_struct(self, tinfo: bn.types.Type) -> Type:
        """Convert bn struct type into a `Type` instance"""

        assert tinfo.type_class == bn.TypeClass.StructureTypeClass

        if tinfo.structure.type == bn.StructureType.UnionStructureType:
            return self._convert_union(tinfo)

        assert (
                tinfo.structure.type == bn.StructureType.StructStructureType
                or tinfo.structure.type == bn.StructureType.ClassStructureType
        )

        ret = StructureType()

        # If struct has no registered name, don't put it in the cache. It
        # is anonymous struct and can cause cache collision
        if tinfo.registered_name:
            self._cache[_cache_key(tinfo)] = ret

        at_offset = [1] * tinfo.width
        num_bytes = len(at_offset)
        at_offset.append(0)

        # figure out what members at what offsets.
        for elem in tinfo.structure.members:
            for i in range(elem.offset, elem.offset + elem.width):
                at_offset[i] = 0
            at_offset[elem.offset] = self._convert_bn_type(elem.type)

        # Introduce padding byte types
        i = 0
        while i < num_bytes:
            if not isinstance(at_offset[i], int):
                i += 1
                continue

            # Accumulate the number of bytes of padding.
            j = i
            num_padding_bytes = 0
            while j <= num_bytes:
                if isinstance(at_offset[j], int):
                    num_padding_bytes += at_offset[j]
                    j += 1
                else:
                    break

            if num_padding_bytes:
                pt = PaddingType()
                pt.set_num_elements(num_padding_bytes)
                at_offset[i] = pt

            i = j

        for elem in at_offset:
            if isinstance(elem, Type):
                ret.add_element_type(elem)

        return ret

    def _convert_union(self, tinfo: bn.types.Type) -> Type:
        """Convert bn union type into a `Type` instance"""

        assert tinfo.structure.type == bn.StructureType.UnionStructureType

        ret = UnionType()

        # If union has no registered name, don't put it in the cache. It
        # is anonymous union and can cause cache collision
        if tinfo.registered_name:
            self._cache[_cache_key(tinfo)] = ret
        for elem in tinfo.structure.members:
            ret.add_element_type(self._convert_bn_type(elem.type))

        return ret

    def _convert_enum(self, tinfo: bn.types.Type) -> Type:
        """Convert bn enum type into a `Type` instance"""

        assert tinfo.type_class == bn.TypeClass.EnumerationTypeClass

        ret = EnumType()

        # If enum has no registered name, don't put it in the cache. It
        # is anonymous enum and can cause cache collision with other
        # anonymous enum
        if tinfo.registered_name:
            self._cache[_cache_key(tinfo)] = ret
        # The underlying type of enum will be an Interger of size info.width
        ret.set_underlying_type(IntegerType(tinfo.width, False))
        return ret

    def _convert_typedef(self, tinfo: bn.types.Type) -> Type:
        """ Convert bn typedef into a `Type` instance"""

        assert tinfo.type_class == \
               bn.NamedTypeReferenceClass.TypedefNamedTypeClass

        ret = TypedefType()
        self._cache[_cache_key(tinfo)] = ret
        ret.set_underlying_type(
            self._convert_bn_type(self._bv.get_type_by_name(tinfo.name))
        )
        return ret

    def _convert_array(self, tinfo: bn.types.Type) -> Type:
        """ Convert bn pointer type into a `Type` instance"""

        assert tinfo.type_class == bn.TypeClass.ArrayTypeClass

        ret = ArrayType()
        self._cache[_cache_key(tinfo)] = ret
        ret.set_element_type(self._convert_bn_type(tinfo.element_type))
        ret.set_num_elements(tinfo.count)
        return ret

    def _convert_pointer(self, tinfo) -> Type:
        """ Convert bn pointer type into a `Type` instance"""

        assert tinfo.type_class == bn.TypeClass.PointerTypeClass

        ret = PointerType()
        self._cache[_cache_key(tinfo)] = ret
        ret.set_element_type(self._convert_bn_type(tinfo.target))
        return ret

    def _convert_function(self, tinfo) -> Type:
        """ Convert bn function type into a `Type` instance"""

        assert tinfo.type_class == bn.TypeClass.FunctionTypeClass

        ret = FunctionType()
        self._cache[_cache_key(tinfo)] = ret
        ret.set_return_type(self._convert_bn_type(tinfo.return_value))

        for var in tinfo.parameters:
            ret.add_parameter_type(self._convert_bn_type(var.type))

        if tinfo.has_variable_arguments:
            ret.set_is_variadic()

        return ret

    def _convert_integer(self, tinfo) -> Type:
        """ Convert bn integer type into a `Type` instance"""

        assert tinfo.type_class == bn.TypeClass.IntegerTypeClass

        # long double ty may get represented as int80_t. If the size
        # of the IntegerTypeClass is [10, 12], create a float type
        # int32_t (int32_t arg1, int80_t arg2 @ st0)
        if tinfo.width in [1, 2, 4, 8, 16]:
            return IntegerType(tinfo.width, True)
        elif tinfo.width in [10, 12]:
            return FloatingPointType(tinfo.width)
        else:
            # if width is not from one specified. get the default size
            # to bv.address_size
            return IntegerType(self._bv.address_size, True)

    def _convert_named_reference(self, tinfo: bn.types.Type) -> Type:
        """ Convert named type references into a `Type` instance"""

        assert tinfo.type_class == bn.TypeClass.NamedTypeReferenceClass
        ref_type = self._bv.get_type_by_id(tinfo.type_id)
        if ref_type is None:
            ref_type = self._bv.get_type_by_name(tinfo.name)
            if ref_type is None:
                return VoidType()

        print("!!! {ref_type.type_class}")
        if tinfo.type_class == bn.NamedTypeReferenceClass.StructNamedTypeClass:
            return self._convert_struct(ref_type)

        elif tinfo.type_class == bn.NamedTypeReferenceClass.UnionNamedTypeClass:
            return self._convert_union(ref_type)

        elif tinfo.type_class == \
                bn.NamedTypeReferenceClass.TypedefNamedTypeClass:
            return self._convert_typedef(ref_type)

        elif tinfo.type_class == bn.NamedTypeReferenceClass.EnumNamedTypeClass:
            return self._convert_enum(ref_type)

        elif tinfo.type_class == \
                bn.NamedTypeReferenceClass.UnknownNamedTypeClass:
            return VoidType()

        else:
            WARN(
                f"WARNING: Unknown named type class {tinfo.type_class} not "
                f"handled")
            return VoidType()

    def _convert_bn_type(self, tinfo: bn.types.Type) -> Type:
        """Convert an bn `Type` instance into a `Type` instance."""

        if _cache_key(tinfo) in self._cache:
            return self._cache[_cache_key(tinfo)]

        # Void type
        if tinfo.type_class == bn.TypeClass.VoidTypeClass:
            return VoidType()

        elif tinfo.type_class == bn.TypeClass.PointerTypeClass:
            return self._convert_pointer(tinfo)

        elif tinfo.type_class == bn.TypeClass.FunctionTypeClass:
            return self._convert_function(tinfo)

        elif tinfo.type_class == bn.TypeClass.ArrayTypeClass:
            return self._convert_array(tinfo)

        elif tinfo.type_class == bn.TypeClass.StructureTypeClass:
            return self._convert_struct(tinfo)

        elif tinfo.type_class == bn.TypeClass.EnumerationTypeClass:
            return self._convert_enum(tinfo)

        elif tinfo.type_class == bn.TypeClass.BoolTypeClass:
            return BoolType()

        elif tinfo.type_class == bn.TypeClass.IntegerTypeClass:
            return self._convert_integer(tinfo)

        elif tinfo.type_class == bn.TypeClass.FloatTypeClass:
            return FloatingPointType(tinfo.width)

        elif tinfo.type_class == bn.TypeClass.NamedTypeReferenceClass:
            return self._convert_named_reference(tinfo)

        elif tinfo.type_class in TypeCache._err_type_class.keys():
            WARN(
                f"WARNING: Unhandled type class "
                f"{TypeCache._err_type_class[tinfo.type_class]}"
            )
            return VoidType()

        else:
            raise UnhandledTypeException(
                "Unhandled type: {}".format(str(tinfo)), tinfo)

    def get(self, ty) -> Type:
        """Type class that gives access to type sizes, printings, etc."""

        if isinstance(ty, Type):
            return ty

        elif isinstance(ty, Function):
            return ty.type()

        elif isinstance(ty, bn.Type):
            return self._convert_bn_type(ty)

        elif not ty:
            return VoidType()

        raise UnhandledTypeException("Unrecognized type passed to `Type`.", ty)
