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


import ctypes


from dataclasses import dataclass
from typing import List


from anvill.imageparser import *


MAX_STRING_LENGTH = 2048
STT_FUNC = 2
SHT_RELA = 4
SHT_REL = 9


@dataclass
class FileHeader:
    """The ELF file header"""

    e_ident: bytes = bytes()
    e_type: int = 0
    e_machine: int = 0
    e_version: int = 0
    e_entry: int = 0
    e_phoff: int = 0
    e_shoff: int = 0
    e_flags: int = 0
    e_ehsize: int = 0
    e_phentsize: int = 0
    e_phnum: int = 0
    e_shentsize: int = 0
    e_shnum: int = 0
    e_shstrndx: int = 0


@dataclass
class SectionHeader:
    """Section header"""

    sh_name: int = 0
    sh_type: int = 0
    sh_flags: int = 0
    sh_addr: int = 0
    sh_offset: int = 0
    sh_size: int = 0
    sh_link: int = 0
    sh_info: int = 0
    sh_addralign: int = 0
    sh_entsize: int = 0


@dataclass
class ELFSymbol:
    """ELF symbol"""

    st_name: int = 0
    st_value: int = 0
    st_size: int = 0
    st_info: int = 0
    st_other: int = 0
    st_shndx: int = 0


@dataclass
class ELFRelocation:
    """ELF relocation"""

    r_offset: int = 0
    r_info: int = 0
    r_addend: int = 0


class ELFParser(ImageParser):
    """This is the parser for ELF images.

    Look at the ImageParser class for more information on the public
    methods implemented here.
    """

    _input_file = None
    _file_header: FileHeader = FileHeader()
    _section_header_list: List[SectionHeader] = []
    _string_table: bytearray = bytearray()
    _symbol_list: List[ELFSymbol] = []
    _function_thunk_list: List[ImageFunctionThunk] = []

    def __init__(self, input_file_path: str):
        """Initializes the ELF image object

        Raises an exception of type IOError if the ELF headers can't
        be read correctly, or RuntimeError if it is not valid

        Args:
            input_file_path: Path to the input file path
        """

        super(ELFParser, self).__init__(input_file_path)

        self._read_file_header()
        self._read_section_header_list()
        self._read_string_table()
        self._parse_symbol_table()
        self._process_function_thunks()

    def get_function_thunk_list(self) -> List[ImageFunctionThunk]:
        """See the ImageParser base class for more information on this method"""

        return self._function_thunk_list

    def get_image_bitness(self) -> int:
        """See the ImageParser base class for more information on this method"""

        # This method requires that the `e_ident` field in the ELF file
        # header has already been read.

        if self._file_header.e_ident[4] == 1:
            return 32
        elif self._file_header.e_ident[4] == 2:
            return 64
        else:
            raise NotImplementedError()

    def _read_file_header(self):
        """Acquires the ELF header,

        The following fields are either 4 or 8 bytes long, depending
        on the bitness of the platform: entry, phoff, shoff

        Raises an exception of type IOError if the header can't
        be read.
        """

        # The _read_uptr becomes usable once `self._file_header.e_ident[4]`
        # is set`
        self._file_header.e_ident = self._read(16)

        self._file_header.e_type = self._read_u16()
        self._file_header.e_machine = self._read_u16()
        self._file_header.e_version = self._read_u32()
        self._file_header.e_entry = self._read_uptr()
        self._file_header.e_phoff = self._read_uptr()
        self._file_header.e_shoff = self._read_uptr()
        self._file_header.e_flags = self._read_u32()
        self._file_header.e_ehsize = self._read_u16()
        self._file_header.e_phentsize = self._read_u16()
        self._file_header.e_phnum = self._read_u16()
        self._file_header.e_shentsize = self._read_u16()
        self._file_header.e_shnum = self._read_u16()
        self._file_header.e_shstrndx = self._read_u16()

    def _read_section_header_list(self):
        """Reads the list of section headers"""

        self._seek(self._file_header.e_shoff)

        for i in range(0, self._file_header.e_shnum):
            section_header = SectionHeader()

            section_header.sh_name = self._read_u32()
            section_header.sh_type = self._read_u32()
            section_header.sh_flags = self._read_uptr()
            section_header.sh_addr = self._read_uptr()
            section_header.sh_offset = self._read_uptr()
            section_header.sh_size = self._read_uptr()
            section_header.sh_link = self._read_u32()
            section_header.sh_info = self._read_u32()
            section_header.sh_addralign = self._read_uptr()
            section_header.sh_entsize = self._read_uptr()

            self._section_header_list.append(section_header)

    def _read_string_table(self):
        """Acquires the string table from the mapped section"""

        if self._file_header.e_shstrndx >= len(self._section_header_list):
            raise RuntimeError("Invalid string table index")

        string_table_header = self._section_header_list[self._file_header.e_shstrndx]
        self._seek(string_table_header.sh_offset)

        size = ctypes.c_int32(string_table_header.sh_size).value
        self._string_table = self._read(size)

    def _get_string_table_entry(self, string_table: bytearray, index: int) -> str:
        """Returns the specified string table entry

        Args:
            string_table: The string table to use for the lookup
            index: The index in the string table

        Returns:
            A valid string in case of success, or None otherwise
        """

        if index >= len(string_table):
            return None

        remaining_bytes = len(string_table) - index
        remaining_bytes = (
            MAX_STRING_LENGTH
            if remaining_bytes > MAX_STRING_LENGTH
            else remaining_bytes
        )

        terminator_index = None

        for i in range(0, remaining_bytes):
            if string_table[index + i] == 0:
                terminator_index = i
                break

        if terminator_index is None:
            return None

        if terminator_index == 0:
            return ""

        return string_table[index : index + terminator_index].decode("utf-8")

    def _get_section_header(self, section_name: str) -> SectionHeader:
        """Returns the header for the given section name

        Args:
            section_name: A valid section name

        Returns:
            A section header in case of success, or None otherwise
        """

        for section_header in self._section_header_list:
            if section_header.sh_name == 0:
                continue

            current_section_name = self._get_string_table_entry(
                self._string_table, section_header.sh_name
            )

            if current_section_name is None:
                continue

            if current_section_name == section_name:
                return section_header

        return None

    def _get_section(self, section_name: str) -> bytearray:
        """Returns the section data for the given section name

        Args:
            section_name: A valid section name

        Returns:
            A byte array containing the section data in case of success, or None otherwise
        """

        section_header = self._get_section_header(section_name)
        if section_header is None:
            return None

        self._seek(section_header.sh_offset)

        size = ctypes.c_int32(section_header.sh_size).value
        return self._read(size)

    def _parse_symbol_table(self):
        """This function parses the symbol table, storing each entry in an list"""

        dynsym_section_header = self._get_section_header(".dynsym")
        if dynsym_section_header is None:
            DEBUG("WARNING: Failed to acquire the '.dynsym' section")
            return

        is_32_bit = self.get_image_bitness() == 32

        symbol_size = 16 if is_32_bit else 24
        symbol_count = int(dynsym_section_header.sh_size / symbol_size)

        for i in range(0, symbol_count):
            symbol_offset = dynsym_section_header.sh_offset + (i * symbol_size)
            self._seek(symbol_offset)

            elf_symbol = ELFSymbol()

            if is_32_bit:
                elf_symbol.st_name = self._read_u32()
                elf_symbol.st_value = self._read_u32()
                elf_symbol.st_size = self._read_u32()
                elf_symbol.st_info = self._read_u8()
                elf_symbol.st_other = self._read_u8()
                elf_symbol.st_shndx = self._read_u16()

            else:
                elf_symbol.st_name = self._read_u32()
                elf_symbol.st_info = self._read_u8()
                elf_symbol.st_other = self._read_u8()
                elf_symbol.st_shndx = self._read_u32()
                elf_symbol.st_value = self._read_u64()
                elf_symbol.st_size = self._read_u64()

            self._symbol_list.append(elf_symbol)

    def _process_function_thunks(self):
        is_32_bit = self.get_image_bitness() == 32

        dynstr_section = self._get_section(".dynstr")
        if dynstr_section is None:
            DEBUG("WARNING: Failed to acquire the '.dynstr' section")
            return

        for section_header in self._section_header_list:
            if section_header.sh_type != SHT_REL and section_header.sh_type != SHT_RELA:
                continue

            section_name = self._get_string_table_entry(
                self._string_table, section_header.sh_name
            )

            section_data = self._get_section(section_name)
            if section_data is None:
                continue

            has_addend = section_header.sh_type == SHT_RELA

            reloc_entry_size = 8 if is_32_bit else 16
            if has_addend:
                reloc_entry_size += 4 if is_32_bit else 8

            reloc_entry_count = int(section_header.sh_size / reloc_entry_size)

            for reloc_index in range(0, reloc_entry_count):
                reloc_offset = reloc_index * reloc_entry_size

                elf_relocation = ELFRelocation()
                symbol_index = 0

                if is_32_bit:
                    elf_relocation.r_offset = int.from_bytes(
                        section_data[reloc_offset : reloc_offset + 4],
                        byteorder="little",
                        signed=False,
                    )

                    elf_relocation.r_info = int.from_bytes(
                        section_data[reloc_offset + 4 : reloc_offset + 8],
                        byteorder="little",
                        signed=False,
                    )

                    if has_addend:
                        elf_relocation.r_addend = int.from_bytes(
                            section_data[reloc_offset + 8 : reloc_offset + 16],
                            byteorder="little",
                            signed=False,
                        )

                else:
                    elf_relocation.r_offset = int.from_bytes(
                        section_data[reloc_offset : reloc_offset + 8],
                        byteorder="little",
                        signed=False,
                    )

                    elf_relocation.r_info = int.from_bytes(
                        section_data[reloc_offset + 8 : reloc_offset + 16],
                        byteorder="little",
                        signed=False,
                    )

                    if has_addend:
                        elf_relocation.r_addend = int.from_bytes(
                            section_data[reloc_offset + 16 : reloc_offset + 24],
                            byteorder="little",
                            signed=False,
                        )

                    symbol_index = elf_relocation.r_info >> 32

                if symbol_index >= len(self._symbol_list):
                    continue

                elf_symbol = self._symbol_list[symbol_index]
                if (elf_symbol.st_info & 0x0F) != STT_FUNC:
                    continue

                symbol_name = self._get_string_table_entry(
                    dynstr_section, elf_symbol.st_name
                )

                function_thunk = ImageFunctionThunk()
                function_thunk.start = elf_relocation.r_offset
                function_thunk.name = symbol_name

                self._function_thunk_list.append(function_thunk)
