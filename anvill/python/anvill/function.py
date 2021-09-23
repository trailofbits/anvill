# Copyright (c) 2020 Trail of Bits, Inc.
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


from .type import Type, FunctionType, StructureType
from .loc import Location
from typing import List


class Function(object):
    """Represents a generic function."""

    __slots__ = (
        "_arch",
        "_address",
        "_parameters",
        "_return_values",
        "_type",
        "_cc",
        "_register_info",
    )

    def __init__(self, arch, address, parameters, return_values, func_type, cc=0):
        assert isinstance(func_type, FunctionType)
        self._arch = arch
        self._address = address
        self._parameters = parameters
        self._return_values = return_values
        self._type = func_type
        self._cc = cc
        self._register_info: List[Location] = []

        for param in self._parameters:
            assert isinstance(param, Location)
            param_type = param.type()
            assert isinstance(param_type, Type)

        if len(self._return_values) == 1:
            ret_val = self._return_values[0]
            assert isinstance(ret_val, Location)
            ret_type = ret_val.type()
            assert isinstance(ret_type, Type)

        elif len(self._return_values):
            str_type = StructureType()
            for ret_val in self._return_values:
                assert isinstance(ret_val, Location)
                ret_type = ret_val.type()
                assert isinstance(ret_type, Type)
                str_type.add_element_type(ret_type)

    def address(self):
        return self._address

    def type(self):
        return self._type

    def calling_convention(self):
        return self._cc

    def visit(self, program, is_definition: bool, add_refs_as_defs: bool):
        raise NotImplementedError()

    def is_declaration(self):
        raise NotImplementedError()

    def is_variadic(self):
        return self._type.is_variadic()

    def is_noreturn(self):
        return False

    def has_return_address(self):
        return True

    def is_external(self):
        return False

    def proto(self):
        proto = {}
        proto["address"] = self.address()
        proto["return_address"] = self._arch.return_address_proto()
        proto["return_stack_pointer"] = self._arch.return_stack_pointer_proto(
            self.type().num_bytes_popped_off_stack()
        )
        if self._parameters:
            proto["parameters"] = [loc.proto(self._arch) for loc in self._parameters]
        if self._return_values:
            proto["return_values"] = [
                loc.proto(self._arch) for loc in self._return_values
            ]
        if self.is_variadic():
            proto["is_variadic"] = True
        if self.is_noreturn():
            proto["is_noreturn"] = True
        if not self.has_return_address():
            proto["has_return_address"] = False
        if self._cc:
            proto["calling_convention"] = self._cc
        if self._register_info:
            proto["register_info"] = [
                loc.proto(self._arch) for loc in self._register_info
            ]

        # The function type information is only available with the
        # functions that are external. The lifter will handle the function
        # types and ignore params and return values
        if self.is_external():
            proto["type"] = self.type().proto(self._arch)

        return proto
