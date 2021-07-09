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


from abc import ABC, abstractmethod
import collections
from dataclasses import dataclass, field
from typing import List, DefaultDict, Dict, Iterator, Optional, Set

from .function import *
from .var import *
from .mem import *
from .exc import *


@dataclass
class ControlFlowTargetList:
    """A list of targets reachable from a given address"""

    source: int = 0
    destination_list: List[int] = field(default_factory=list)
    complete: bool = False


class Program(ABC):
    """Represents a program."""

    def __init__(self, arch, os):
        self._arch = arch
        self._os = os
        self._memory = Memory()
        self._var_defs: Dict[int, Variable] = {}
        self._var_decls: Dict[int, Variable] = {}
        self._func_defs: Dict[int, Function] = {}
        self._func_decls: Dict[int, Function] = {}
        self._control_flow_redirections: Dict[int, int] = {}
        self._control_flow_targets: Dict[int, ControlFlowTargetList] = {}
        self._symbols: DefaultDict[int, Set[str]] = collections.defaultdict(set)

    def get_symbols(self, ea) -> Iterator[str]:
        syms = self._symbols[ea]
        if ea in self._symbols:
            yield from iter(syms)
        else:
            for name in self.get_symbols_impl(ea):
                old_len = len(syms)
                syms.add(name)
                if old_len < len(syms):
                    yield name

    @abstractmethod
    def function_from_addr(self, ea: int):
        ...

    def get_function(self, ea: int) -> Optional[Function]:
        bn_func = self.function_from_addr(ea)

        # If this address is already in a function, then
        # check if we processed it already
        if bn_func:
            ea = bn_func.start
        if ea in self._func_defs:
            assert ea not in self._func_decls
            return self._func_defs[ea]
        elif ea in self._func_decls:
            return self._func_decls[ea]
        else:
            return self.get_function_impl(ea)

    def get_variable(self, ea: int) -> Optional[Variable]:
        if ea in self._var_defs:
            assert ea not in self._var_decls
            return self._var_defs[ea]
        elif ea in self._var_decls:
            return self._var_decls[ea]
        else:
            return self.get_variable_impl(ea)

    @abstractmethod
    def get_symbols_impl(self, ea: int) -> Iterator[str]:
        ...

    @abstractmethod
    def get_function_impl(self, ea: int) -> Optional[Function]:
        ...

    @abstractmethod
    def get_variable_impl(self, ea: int) -> Optional[Variable]:
        ...

    def add_symbol(self, ea: int, name: str):
        if len(name):
            self._symbols[ea].add(name)

    def add_variable_declaration(self, ea: int, add_refs_as_defs=False) -> bool:
        var = self.get_variable(ea)
        if isinstance(var, Variable):
            ea = var.address()
            if ea not in self._var_defs and ea not in self._var_decls:
                self._var_decls[ea] = var
                var.visit(self, False, add_refs_as_defs)
            return True
        else:
            return False

    def add_control_flow_redirection(self, source_ea: int, destination_ea: int):
        assert isinstance(source_ea, int)
        assert isinstance(destination_ea, int)

        self.try_add_referenced_entity(source_ea, False)
        self.try_add_referenced_entity(destination_ea, False)
        self._control_flow_redirections[source_ea] = destination_ea

    def add_variable_definition(self, ea: int, add_refs_as_defs=False) -> bool:
        var = self.get_variable(ea)
        if isinstance(var, Variable):
            ea = var.address()
            if ea not in self._var_defs:
                if ea in self._var_decls:
                    del self._var_decls[ea]
                self._var_defs[ea] = var
                var.visit(self, True, add_refs_as_defs)
            return True
        else:
            return False

    def add_function_definition(self, ea: int, add_refs_as_defs=False) -> bool:
        func = self.get_function(ea)
        if isinstance(func, Function):
            ea = func.address()
            if ea not in self._func_defs:
                if ea in self._func_decls:
                    del self._func_decls[ea]
                self._func_defs[ea] = func
                func.visit(self, True, add_refs_as_defs)
            return True
        else:
            return False

    def add_function_declaration(self, ea: int, add_refs_as_defs=False) -> bool:
        func = self.get_function(ea)
        if isinstance(func, Function):
            ea = func.address()
            if ea not in self._func_defs and ea not in self._func_decls:
                self._func_decls[ea] = func
                func.visit(self, False, add_refs_as_defs)
            return True
        else:
            return False

    def set_control_flow_targets(
        self, source_ea: int, destination_list: List[int], complete: bool
    ) -> bool:

        self.try_add_referenced_entity(source_ea, False)
        for dest_ea in destination_list:
            self.try_add_referenced_entity(dest_ea, False)

        if source_ea in self._control_flow_targets:
            return False

        entry = ControlFlowTargetList()
        entry.source = source_ea
        entry.destination_list = destination_list
        entry.complete = complete

        self._control_flow_targets[entry.source] = entry
        return True

    def try_add_referenced_entity(self, ea: int, add_refs_as_defs=False) -> bool:
        if add_refs_as_defs:
            try:
                self.add_function_definition(ea, add_refs_as_defs)
                return True
            except InvalidFunctionException as e1:
                try:
                    self.add_variable_definition(ea, add_refs_as_defs)
                    return True
                except InvalidVariableException as e2:
                    pass
        try:
            self.add_function_declaration(ea, False)
            return True
        except InvalidFunctionException as e1:
            try:
                self.add_variable_declaration(ea, False)
                return True
            except InvalidVariableException as e2:
                return False

    @property
    def memory(self) -> Memory:
        return self._memory

    def proto(self) -> Dict:
        proto = {}
        proto["arch"] = self._arch.name()
        proto["os"] = self._os.name()
        proto["functions"] = []
        proto["control_flow_redirections"] = []
        proto["control_flow_targets"] = []
        proto["variables"] = []
        proto["symbols"] = []

        for ea, names in self._symbols.items():
            for name in names:
                proto["symbols"].append([ea, name])

        for func in self._func_decls.values():
            proto["functions"].append(func.proto())

        for func in self._func_defs.values():
            proto["functions"].append(func.proto())

        for source, target in self._control_flow_redirections.items():
            # Use 2-entry lists so that we don't use 'source' as a key. That
            # would turn it into a string in the final JSON forcing us to
            # handle integers in two different ways
            proto["control_flow_redirections"].append([source, target])

        for entry in self._control_flow_targets.values():
            obj = {}
            obj["complete"] = entry.complete
            obj["source"] = entry.source
            obj["destination_list"] = entry.destination_list

            proto["control_flow_targets"].append(obj)

        for var in self._var_decls.values():
            proto["variables"].append(var.proto())

        for var in self._var_defs.values():
            proto["variables"].append(var.proto())

        proto["memory"] = self._memory.proto()

        return proto
