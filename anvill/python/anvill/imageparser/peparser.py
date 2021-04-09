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
from dataclasses import dataclass, field
from typing import List, Tuple


from anvill.imageparser import *


_IMAGE_FILE_MACHINE_AMD64 = 0x8664
_IMAGE_FILE_MACHINE_ARM64 = 0xAA64

_IMAGE_DIRECTORY_ENTRY_IMPORT = 1

_IMAGE_SIZE_OF_SHORT_NAME = 8

_IMAGE_ORDINAL_FLAG = 0x80000000


@dataclass
class ImageDosHeader:
    """The PE DOS header"""

    e_magic: int = 0
    e_cblp: int = 0
    e_cp: int = 0
    e_crlc: int = 0
    e_cparhdr: int = 0
    e_minalloc: int = 0
    e_maxalloc: int = 0
    e_ss: int = 0
    e_sp: int = 0
    e_csum: int = 0
    e_ip: int = 0
    e_cs: int = 0
    e_lfarlc: int = 0
    e_ovno: int = 0
    e_res: List[int] = field(default_factory=list)
    e_oemid: int = 0
    e_oeminfo: int = 0
    e_res2: List[int] = field(default_factory=list)
    e_lfanew: int = 0


@dataclass
class ImageFileHeader:
    """The NT file header"""

    Machine: int = 0
    NumberOfSections: int = 0
    TimeDateStamp: int = 0
    PointerToSymbolTable: int = 0
    NumberOfSymbols: int = 0
    SizeOfOptionalHeader: int = 0
    Characteristics: int = 0


@dataclass
class ImageDataDirectory:
    """Describe the rva and size of a data directory"""

    VirtualAddress: int = 0
    Size: int = 0


@dataclass
class ImageOptionalHeader:
    """The NT optional header"""

    Magic: int = 0
    MajorLinkerVersion: int = 0
    MinorLinkerVersion: int = 0
    SizeOfCode: int = 0
    SizeOfInitializedData: int = 0
    SizeOfUninitializedData: int = 0
    AddressOfEntryPoint: int = 0
    BaseOfCode: int = 0
    BaseOfData: int = 0
    ImageBase: int = 0
    SectionAlignment: int = 0
    FileAlignment: int = 0
    MajorOperatingSystemVersion: int = 0
    MinorOperatingSystemVersion: int = 0
    MajorImageVersion: int = 0
    MinorImageVersion: int = 0
    MajorSubsystemVersion: int = 0
    MinorSubsystemVersion: int = 0
    Win32VersionValue: int = 0
    SizeOfImage: int = 0
    SizeOfHeaders: int = 0
    CheckSum: int = 0
    Subsystem: int = 0
    DllCharacteristics: int = 0
    SizeOfStackReserve: int = 0
    SizeOfStackCommit: int = 0
    SizeOfHeapReserve: int = 0
    SizeOfHeapCommit: int = 0
    LoaderFlags: int = 0
    NumberOfRvaAndSizes: int = 0
    DataDirectory: List[ImageDataDirectory] = field(default_factory=list)


@dataclass
class ImageNTHeaders:
    """The NT headers"""

    Signature: int = 0
    FileHeader: ImageFileHeader = ImageFileHeader()
    OptionalHeader: ImageOptionalHeader = ImageOptionalHeader()


@dataclass
class ImageImportDescriptor:
    """Describes how a module is imported through the import table"""

    OriginalFirstThunk: int = 0
    TimeDateStamp: int = 0
    ForwarderChain: int = 0
    Name: int = 0
    FirstThunk: int = 0


@dataclass
class ImageSectionHeader:
    """An single section header"""

    Name: str = ""
    VirtualSize: int = 0
    VirtualAddress: int = 0
    SizeOfRawData: int = 0
    PointerToRawData: int = 0
    PointerToRelocations: int = 0
    PointerToLinenumbers: int = 0
    NumberOfRelocations: int = 0
    NumberOfLinenumbers: int = 0
    Characteristics: int = 0


class PEParser(ImageParser):
    """This is the parser for PE images.

    Look at the ImageParser class for more information on the public
    methods implemented here.
    """

    _dos_header: ImageDosHeader = ImageDosHeader()
    _nt_headers: ImageNTHeaders = ImageNTHeaders()
    _section_header_list: List[ImageSectionHeader] = []
    _import_descriptor_list: List[ImageImportDescriptor] = []
    _function_thunk_list: List[ImageFunctionThunk] = []

    def __init__(self, input_file_path: str):
        """Initializes the PE image object

        Raises an exception of type IOError if the PE headers can't
        be read correctly, or RuntimeError if it is not valid

        Args:
            input_file_path: Path to the input file path
        """

        super(PEParser, self).__init__(input_file_path)

        self._read_dos_header()
        self._read_nt_headers()
        self._read_section_headers()
        self._read_import_data_directory()
        self._process_function_thunks()

    def get_function_thunk_list(self) -> List[ImageFunctionThunk]:
        """See the ImageParser base class for more information on this method"""
        return self._function_thunk_list

    def get_image_bitness(self) -> int:
        """See the ImageParser base class for more information on this method"""

        # This method requires that the IMAGE_FILE_HEADER structure in the
        # NT headers has been initialized
        if (
            self._nt_headers.FileHeader.Machine == _IMAGE_FILE_MACHINE_AMD64
            or self._nt_headers.FileHeader.Machine == _IMAGE_FILE_MACHINE_ARM64
        ):
            return 64
        else:
            return 32

    def _read_dos_header(self):
        """Acquires the DOS header,

        Raises an exception of type IOError if the header can't
        be read.
        """

        self._dos_header.e_magic = self._read_u16()
        self._dos_header.e_cblp = self._read_u16()
        self._dos_header.e_cp = self._read_u16()
        self._dos_header.e_crlc = self._read_u16()
        self._dos_header.e_cparhdr = self._read_u16()
        self._dos_header.e_minalloc = self._read_u16()
        self._dos_header.e_maxalloc = self._read_u16()
        self._dos_header.e_ss = self._read_u16()
        self._dos_header.e_sp = self._read_u16()
        self._dos_header.e_csum = self._read_u16()
        self._dos_header.e_ip = self._read_u16()
        self._dos_header.e_cs = self._read_u16()
        self._dos_header.e_lfarlc = self._read_u16()
        self._dos_header.e_ovno = self._read_u16()

        for i in range(0, 4):
            self._dos_header.e_res.append(self._read_u16())

        self._dos_header.e_oemid = self._read_u16()
        self._dos_header.e_oeminfo = self._read_u16()

        for i in range(0, 10):
            self._dos_header.e_res2.append(self._read_u16())

        self._dos_header.e_lfanew = self._read_u32()

    def _read_nt_headers(self):
        """Acquires the NT headers

        Throws an exception of type IOError if the header can't
        be read
        """

        self._input_file.seek(self._dos_header.e_lfanew)

        # PE signature
        self._nt_headers.Signature = self._read_u32()

        # File Header
        self._nt_headers.FileHeader.Machine = self._read_u16()
        self._nt_headers.FileHeader.NumberOfSections = self._read_u16()
        self._nt_headers.FileHeader.TimeDateStamp = self._read_u32()
        self._nt_headers.FileHeader.PointerToSymbolTable = self._read_u32()
        self._nt_headers.FileHeader.NumberOfSymbols = self._read_u32()
        self._nt_headers.FileHeader.SizeOfOptionalHeader = self._read_u16()
        self._nt_headers.FileHeader.Characteristics = self._read_u16()

        # Optional Header
        self._nt_headers.OptionalHeader.Magic = self._read_u16()
        self._nt_headers.OptionalHeader.MajorLinkerVersion = self._read_u8()
        self._nt_headers.OptionalHeader.MinorLinkerVersion = self._read_u8()
        self._nt_headers.OptionalHeader.SizeOfCode = self._read_u32()
        self._nt_headers.OptionalHeader.SizeOfInitializedData = self._read_u32()
        self._nt_headers.OptionalHeader.SizeOfUninitializedData = self._read_u32()
        self._nt_headers.OptionalHeader.AddressOfEntryPoint = self._read_u32()
        self._nt_headers.OptionalHeader.BaseOfCode = self._read_u32()

        if self.get_image_bitness() == 32:
            self._nt_headers.OptionalHeader.BaseOfData = self._read_u32()
            self._nt_headers.OptionalHeader.ImageBase = self._read_u32()
        else:
            self._nt_headers.OptionalHeader.ImageBase = self._read_u64()

        self._nt_headers.OptionalHeader.SectionAlignment = self._read_u32()
        self._nt_headers.OptionalHeader.FileAlignment = self._read_u32()
        self._nt_headers.OptionalHeader.MajorOperatingSystemVersion = self._read_u16()
        self._nt_headers.OptionalHeader.MinorOperatingSystemVersion = self._read_u16()
        self._nt_headers.OptionalHeader.MajorImageVersion = self._read_u16()
        self._nt_headers.OptionalHeader.MinorImageVersion = self._read_u16()
        self._nt_headers.OptionalHeader.MajorSubsystemVersion = self._read_u16()
        self._nt_headers.OptionalHeader.MinorSubsystemVersion = self._read_u16()
        self._nt_headers.OptionalHeader.Win32VersionValue = self._read_u32()
        self._nt_headers.OptionalHeader.SizeOfImage = self._read_u32()
        self._nt_headers.OptionalHeader.SizeOfHeaders = self._read_u32()
        self._nt_headers.OptionalHeader.CheckSum = self._read_u32()
        self._nt_headers.OptionalHeader.Subsystem = self._read_u16()
        self._nt_headers.OptionalHeader.DllCharacteristics = self._read_u16()

        self._nt_headers.OptionalHeader.SizeOfStackReserve = self._read_uptr()
        self._nt_headers.OptionalHeader.SizeOfStackCommit = self._read_uptr()
        self._nt_headers.OptionalHeader.SizeOfHeapReserve = self._read_uptr()
        self._nt_headers.OptionalHeader.SizeOfHeapCommit = self._read_uptr()

        self._nt_headers.OptionalHeader.LoaderFlags = self._read_u32()
        self._nt_headers.OptionalHeader.NumberOfRvaAndSizes = self._read_u32()

        for _ in range(0, self._nt_headers.OptionalHeader.NumberOfRvaAndSizes):
            data_directory = ImageDataDirectory()
            data_directory.VirtualAddress = self._read_u32()
            data_directory.Size = self._read_u32()

            self._nt_headers.OptionalHeader.DataDirectory.append(data_directory)

    def _read_section_headers(self):
        """Reads the section headers from the PE file"""

        # first section header: nt headers offset + signature + file header = optional header size
        offset = (
            self._dos_header.e_lfanew
            + 24
            + self._nt_headers.FileHeader.SizeOfOptionalHeader
        )
        self._input_file.seek(offset)

        for _ in range(0, self._nt_headers.FileHeader.NumberOfSections):
            section_header = ImageSectionHeader()

            section_name = self._read(_IMAGE_SIZE_OF_SHORT_NAME)
            section_header.Name = section_name.decode("utf-8")

            section_header.VirtualSize = self._read_u32()
            section_header.VirtualAddress = self._read_u32()
            section_header.SizeOfRawData = self._read_u32()
            section_header.PointerToRawData = self._read_u32()
            section_header.PointerToRelocations = self._read_u32()
            section_header.PointerToLinenumbers = self._read_u32()
            section_header.NumberOfRelocations = self._read_u16()
            section_header.NumberOfLinenumbers = self._read_u16()
            section_header.Characteristics = self._read_u32()

            self._section_header_list.append(section_header)

    def _rva_to_file_offset(self, rva: int) -> int:
        """Converts an rva to a file offset"""

        for section_header in self._section_header_list:
            section_size = section_header.SizeOfRawData
            if section_size == 0:
                section_size = section_header.VirtualSize

            if (
                rva >= section_header.VirtualAddress
                and rva < section_header.VirtualAddress + section_size
            ):

                file_offset = section_header.PointerToRawData + (
                    rva - section_header.VirtualAddress
                )
                return file_offset

        return None

    def _read_import_data_directory(self):
        """Reads the import data directory"""

        if _IMAGE_DIRECTORY_ENTRY_IMPORT > len(
            self._nt_headers.OptionalHeader.DataDirectory
        ):
            return

        import_data_dir = self._nt_headers.OptionalHeader.DataDirectory[
            _IMAGE_DIRECTORY_ENTRY_IMPORT
        ]

        offset = self._rva_to_file_offset(import_data_dir.VirtualAddress)
        if offset is None:
            return

        self._input_file.seek(offset)

        while True:
            import_descriptor = ImageImportDescriptor()
            import_descriptor.OriginalFirstThunk = self._read_u32()
            import_descriptor.TimeDateStamp = self._read_u32()
            import_descriptor.ForwarderChain = self._read_u32()
            import_descriptor.Name = self._read_u32()

            import_descriptor.FirstThunk = self._read_u32()
            if import_descriptor.FirstThunk == 0:
                break

            self._import_descriptor_list.append(import_descriptor)

    def _process_function_thunks(self):
        """Processes the import data directory to generate the function thunk list"""

        for import_descriptor in self._import_descriptor_list:
            module_name_offset = self._rva_to_file_offset(import_descriptor.Name)
            if module_name_offset is None:
                break

            self._input_file.seek(module_name_offset)
            module_name = self._read_str()

            thunk_array_offset = self._rva_to_file_offset(import_descriptor.FirstThunk)
            if thunk_array_offset is None:
                break

            self._seek(thunk_array_offset)
            thunk_entry_list: List[Tuple[int, int]] = []

            while True:
                thunk_destination = self._read_uptr()
                if thunk_destination == 0:
                    break

                thunk_rva = import_descriptor.FirstThunk + (
                    len(thunk_entry_list) * int(self.get_image_bitness() / 8)
                )

                thunk_entry = (thunk_rva, thunk_destination)
                thunk_entry_list.append(thunk_entry)

            for thunk_rva, thunk_destination in thunk_entry_list:
                by_ordinal = (thunk_destination & _IMAGE_ORDINAL_FLAG) != 0
                thunk_destination = thunk_destination & (~_IMAGE_ORDINAL_FLAG)

                function_name = ""

                if by_ordinal:
                    function_name = "#" + str(thunk_destination)

                else:
                    thunk_file_offset = self._rva_to_file_offset(thunk_destination)
                    self._seek(thunk_file_offset)

                    hint = self._read_u16()
                    name = self._read_str()

                    function_name = name

                image_function_thunk = ImageFunctionThunk()
                image_function_thunk.start = thunk_rva
                image_function_thunk.name = function_name

                self._function_thunk_list.append(image_function_thunk)
