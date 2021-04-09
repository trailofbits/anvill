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
from dataclasses import dataclass
from typing import List

from anvill.util import *


_MAX_STRING_SIZE = 1024


@dataclass
class ImageFunctionThunk:
    """A function thunk, used to call imported functions"""

    start: int = 0
    name: str = ""


class ImageParser:
    """This is the interface for image parser classes"""

    _input_file = None

    def __init__(self, input_file_path: str):
        """Initializes the base ImageParser class, opening the input file

        Args:
            input_file_path: Path to the input file path
        """

        self._input_file = open(input_file_path, "rb")

    def _seek(self, offset: int):
        """Moves the current read offset"""

        self._input_file.seek(offset)

    def _read(self, size: int) -> bytearray:
        """Reads the specified amount of bytes from the current offset

        Args:
            size: How many bytes to read

        Returns:
            The buffer of size `size` from the current offset
        """

        read_buffer = self._input_file.read(size)
        if len(read_buffer) != size:
            raise IOError()

        return read_buffer

    def _read_str(self) -> str:
        """Reads a null-terminated string from the current offset

        Returns:
            A string, read from the current offset
        """

        buffer: bytearray = bytearray()

        for _ in range(0, _MAX_STRING_SIZE):
            byte = self._read(1)

            as_int = int.from_bytes(byte, byteorder="little", signed=False)
            if as_int == 0:
                break

            buffer += byte

        return buffer.decode("utf-8")

    def _read_u8(self) -> int:
        """Reads an 8-bit unsigned integer from the current offset

        Returns:
            The u8 at the current offset
        """

        return int.from_bytes(self._read(1), byteorder="little", signed=False)

    def _read_u16(self) -> int:
        """Reads a 16-bit unsigned integer from the current offset

        Returns:
            The u16 at the current offset
        """

        return int.from_bytes(self._read(2), byteorder="little", signed=False)

    def _read_u32(self) -> int:
        """Reads a 32-bit unsigned integer from the current offset

        Returns:
            The u32 at the current offset
        """

        return int.from_bytes(self._read(4), byteorder="little", signed=False)

    def _read_u64(self) -> int:
        """Reads a 64-bit unsigned integer from the current offset

        Returns:
            The u64 at the current offset
        """

        return int.from_bytes(self._read(8), byteorder="little", signed=False)

    def _read_uptr(self) -> int:
        """Reads a ptr-sized unsigned integer from the current offset

        Returns:
            The ptr-sized integer at the current offset
        """

        type_size = int(self.get_image_bitness() / 8)
        return int.from_bytes(self._read(type_size), byteorder="little", signed=False)

    @abstractmethod
    def get_function_thunk_list(self) -> List[ImageFunctionThunk]:
        """Returns a list of function thunks found in the image"""

        pass

    @abstractmethod
    def get_image_bitness(self) -> int:
        """Returns the bitness of this image (i.e. 16, 32, 64)"""

        pass


from .elfparser import *
from .peparser import *


def create_elf_image_parser(input_file_path: str) -> ImageParser:
    """Creates a new ImageParser object for ELF files

    Args:
        The path to the input file

    Returns:
        An image parser object for ELF files
    """

    return ELFParser(input_file_path)


def create_pe_image_parser(input_file_path: str) -> ImageParser:
    """Creates a new ImageParser object for PE files

    Args:
        The path to the input file

    Returns:
        An image parser object for ELF files
    """

    return PEParser(input_file_path)
