# Specification Format

Anvill encodes information in "specification" JSON documents. These documents encode
low-level ABI information about functions and global variables. They are not meant
to encode all information about a single binary. In fact, the design is geared toward
using many documents to represent a single binary.

## Example of a JSON specification document

```json
{
    "arch": "amd64",
    "os": "linux",
    "functions": [
        {
            "address": 4416,
            "return_address": {
                "memory": {
                    "register": "RSP",
                    "offset": 0
                },
                "type": "L"
            },
            "return_stack_pointer": {
                "register": "RSP",
                "offset": 8,
                "type": "L"
            },
            "parameters": [
                {
                    "register": "RDI",
                    "type": "i"
                },
                {
                    "register": "RSI",
                    "type": "**b"
                },
                {
                    "register": "RDX",
                    "type": "**b"
                }
            ],
            "return_values": [
                {
                    "register": "RAX",
                    "type": "i"
                }
            ]
        }
    ],
    "variables": [],
    "symbols": [
        [
            4416,
            "__libc_csu_init"
        ]
    ],
    "memory": [
        {
            "address": 4416,
            "is_writeable": false,
            "is_executable": true,
            "data": "f30f1efa41574c8d3da32c000041564989d641554989f541544189fc55488d2d942c0000534c29fd4883ec08e88ffeffff48c1fd03741f31db0f1f80000000004c89f24c89ee4489e741ff14df4883c3014839dd75ea4883c4085b5d415c415d415e415fc3"
        },
    ]
}
```

## Basic structure of a JSON specification document

### Format

All documents are a single object. The object is a specification for zero-or-more
functions, zero-or-more global variables, and any associated memory mappings or
symbol mappings.

```json
{
```

### Architecture

All documents specify a single architecture which applies to the functions and
variables covered by the document. The architecture governs the endianness of memory
accesses, the instruction decoder to use, and the register set referenced by value
specifications.

```json
    "arch": "amd64",
```

The following is a list of available architectures. Architecture names are
case-sensitive.

| Name | Address Width | Endianness | Description |
|--|--|--|--|
| x86 | 32 | Little | x86 architecture, including x87, MMX and SSE instruction sets. |
| x86_avx | 32 | Little | x86 architecture, including x87, MMX, SSE, and AVX instruction sets. |
| x86_avx512 | 32 | Little | x86 architecture, including x87, MMX, SSE, AVX, and AVX512 instruction sets. |
| amd64 | 64 | Little | x86-64 architecture, including x87, MMX and SSE instruction sets. |
| amd64_avx | 64 | Little | x86-64 architecture, including x87, MMX, SSE, and AVX instruction sets. |
| amd64_avx512 | 64 | Little | x86-64 architecture, including x87, MMX, SSE, AVX, and AVX512 instruction sets. |
| aarch64 | 64 | Little | ARMv8 64-bit architecture, inclding NEON. |
| aarch32 | 32 | Little | ARMv8 32-bit architecture, backwards-compatible with ARMv7. |
| sparc32 | 32 | Big | SPARCv8+ architecture. |
| sparc64 | 64 | Big | SPARCv9 architecture. |

If a given binary contains code for multiple architectures, then separate documents
should be used to represent those portions of code.

### Operating systems

All documents specify a single operation system which applies to the code and data
in the document.

```json
    "os": "linux",
```

Users of specification documents may support information side-channels, e.g. that tie
together symbol names and function prototypes, or tie together byte patterns
to symbol names and function prototypes (e.g. via IDA's FLIRT). The combination of
architecture name and operating system name is the minimum amount of information
necessary to convert a function prototype into a low-level specification.

The following is a list of available operating system names. Operating system
names are case-sensitive. Operating system names are not tied to a specific version
of the operating system. That is, there is no distinction between Windows XP and
Windows 10.

| Name | Description |
|--|--|
| linux | Linux |
| macos | Apple macOS |
| windows | Microsoft Windows |
| solaris | Sun/Oracle Solaris |

### Function list

The function list is a JSON array containing function declaration objects.

```json
    "functions": [
```

Function declaration objects package up information sufficient to perform the
following actions:

 * Generate a valid function call. That is, given the desire to call a function
   some arguments, the specification of a function describes where the arguments
   of a function must be placed (e.g. in which registers, in memory on the stack,
   etc.)
 * Extract arguments, given that one is at the entrypoint of a function.
 * Extract one or more return values from machine state, just after a function
   call has returned.
 * Store return values into the machine state, prior to a function's return.

#### Address

Functions in a specification are identified by their address, and thus it is
required that no two functions in the same document share the same address. All
functions must have an address, even external functions (e.g. functions located
in a shared library, whose addresses may be as-of-yet unknown).

The address associated with a function does not need to be associated with a
range in the `memory` section of the document. A function whose address is not
covered by any memory range is treated as an external declaration. In this
context, "external" implies "external to what is represented by the document"
and does not imply "external to the binary from which the specification is derived."

```json
        {
            "address": 4416,
```

#### Return address

The return address is a "value declaration" object. It describes the type of
a value (i.e. the type of a return address), as well as where that value resides
on entry to the function. "On entry to the function" has the specific meaning of
immediately before the first instruction of a function has executed.

```json
            "return_address": {
                "memory": {
                    "register": "RSP",
                    "offset": 0
                },
                "type": "L"
            },
```

The above value has type `L` representing `uint64_t` (see the [Type Encoding](TypeEncoding.md)
documentation). The value resides in `"memory`", at the address contained in `RSP`,
plus the signed offset `0`. Recall that in these specifications, all values relate to
the state of registers/memory just before the first instruction of the function executes,
and thus `RSP` here means the value contained in `RSP` just before the first instruction
executed.

This example specification document is for x86-64 code, and so this spec says that
`QWORD [RSP]` is the location of the return address on entry to the function. For 32-bit
x86, we would want to model `DWORD [ESP]`. That would be representable with the
following JSON:

```json
{"memory": {"register": "ESP", "offset": 0}, "type": "I"}
```

For AArch64, the return address is passed throught the link pointer register, and
thus would be represented with the following JSON:

```json
{"register": "LR", "type": "L"}
```

In the above examples, we've represented return address types with integral type
names; however, it is perfectly valid to represent them using pointer types, e.g.
`*v` or `*b` or `*B`.

#### Return stack pointer

A function specification models the value of the stack pointer *after* returning
from the function, with respect to the register/machine state just before entering
the function. The below example specification says that the value of the stack pointer
after returning from the function will be the value of the `RSP` register on entry
to the function, interpreted as an eight-byte integer (`L`), plus eight.

```json
            "return_stack_pointer": {
                "register": "RSP",
                "offset": 8,
                "type": "L"
            },
```

One way of interpreting this value is that it represents how much the stack pointer
is displaced by popping the return address off the stack, and possibly doing any
callee cleanup. For example, some calling conventions on x86/amd64 use the
`retn <imm>`. In this case, we would say that the value of `offset` would be
`<pointer size> + <imm>`.

#### Parameters

Function parameter lists are specified using a JSON array. A function with no
parameters should specify an empty JSON array.

```json
            "parameters": [
```

##### Parameter specifications

A parameter specification describes the type of the parameter, an optional
name, as well as where that parameter resides (expressed in terms of register/machine
state on entry to the function).

In the below JSON, there is a parameter named `argc`, stored in the `RDI` register,
with type `int32_t`. In this case, `int32_t` does not fully cover the space that
can be covered by the `RDI` register, and so the low four bytes of the eight byte
`RDI` register are used.

```json
                {
                    "register": "RDI",
                    "type": "i",
                    "name": "argc"
                },
```

Parameter values can also reside in memory. For example, a parameter passed on
the stack may be specified as follows.

```json
                {
                    "memory": {
                      "register": "ESP",
                      "offset": 4
                    },
                    "type": "i",
                },
```

Note that parameters in this representation do not necessarily have a one-to-one
relationship with parameters in higher-level languages, such as C. Specifically,
if multiple parameters are passed in a single register, then that is represented
as a single parameter in the spec. Similarly, if a single parameter is split
across multiple registers then each destructured component is represented with a
separate parameter specification object in this representation.

#### Return values

Like parameters, return values are a list of value declarations, where the values
are typed, and reside in registers or memory. Unlike parameters, return values
don't have names. Multiple return values are interpreted as belonging to a packed
structure.

```json
            "return_values": [
                {
                    "register": "RAX",
                    "type": "i"
                }
            ]
```

Note that return value optimization is a higher-level concept than this representation.
Specifically, return-value optimization (e.g. in the SysV AMD64 ABI) would be represented
as the first argument (`RDI`) and the return value (`RAX`) both having the same pointer
type.

#### Variadic functions

If the function being specified is variadic, then the following must be provided.

```json
            "is_variadic": true,
```

The absence of `is_variadic`, as well as a `false` value to `is_variadic`, are
treated identically as meaning "the function is not variadic."

#### No-return functions

If the function being specified does not return, e.g. ends with a call to
`abort()`, then the following can be optionally provided to improve the accuracy
of lifting.

```json
            "is_noreturn": true,
```

The absence of `is_noreturn`, as well as a `false` value to `is_noreturn`, are
treated identically as meaning "the function returns sometimes or always." We
say sometimes because some functions may conditionally invoke `longjmp`, or
conditionally throw an exception, and thus returns may not always be guaranteed.

#### Return addresses

If the function being specified does not have a return address (it is the
program entrypoint), then the following must be provided.

```json
            "has_return_address": false,
```

The absence of `has_return_address`, as well as a `true` value to
`has_return_address`, are treated identically meaning "the function has a return
address".

#### Calling convention

The calling convention of a function specification should be specified. At first
this may seem redundant, as the specification tells us the locations of all relevant
data needed to call a function, or to marhsal its arguments and return values.

The specification format, however, is also meant to describe how to declare a
higher-level LLVM function that, if compiled, will access all of the same data
locations when operating on parameters and return values. In order to follow through
on this end-to-end idea, the LLVM code generator needs to know the calling convention
of the function. Thus, we encourange the calling convention be specified. The absence
of a calling convention implies the "default" calling convention for an architecture
and operating system pair.

Calling conventions are specified as an integral value which corresponds directly
to LLVM's internal calling convention representation.

```json
            "calling_convention": 0,
```

The following table documents the supported calling conventions. A more exhaustive
list can be found [here](https://code.woboq.org/llvm/llvm/include/llvm/IR/CallingConv.h.html#29).

| Integral value | Description |
|--|--|
| 0 | Default calling convention for C functions |
| 64 | `stdcall` on x86 |
| 65 | `fastcall` on x86 |
| 70 | `thiscall` on x86|
| 78 | AMD64 SysV ABI, default on Linux and macOS on x86-64 |
| 79 | Win64 |
| 80 | `vectorcall` on x86 |

### Global variables

Global variables are specified in a top-level list. Like functions, global variables
are unnamed, and uniquely identified by their addresses.

```json
    "variables": [
```

A global variable specification is an object containing the address and the type
of the variable. The address does not need to correspond with a range described
in the `memory` region of the specification. A global variable referencing a
non-existent memory region without data is treated as "external to the specification."

```
        {
            "type": "i",
            "address": 12345
        }
```

### Symbol names

Multiple locations in a binary may share the same symbol name. For example, it is
common for there to be a symbol referring to one byte past the end of a section.
When there is another section immediately following, and if the first byte of that
section is also named, then the two symbols will correspond with the same logical
address.

Symbols names are represented as a list of lists, logically a list of tuples,
where the tuples have their first entry as an address, and their second entry
as a string representation of the symbol name. For example:

```json
    "symbols": [
        [
            4416,
            "__libc_csu_init"
        ]
    ],
```

### Memory

Memory is specified as a list of memory range specifications.

```json
    "memory": [
```

#### Memory range specifications.

Memory range specifications are objects describing a linear slice of memory.
Ranges have a designated begin address, represented by `address`, and an implied
size, which is the length of the `data` string divided by two. There are no
alignment or minimum/maximum size requirements on the `address` or `data` fields.

Concrete data must be provided for each memory range, in the form of a hex-encoded
string of bytes in the `data` field. Thus, this field must always be present and
contain a non-empty string of even size and whose characters are accepted by the
regular expression character class `[0-9a-fA-F]`.

Memory ranges are considered "permissioned" and are all treated as implicitly
readable. A range can be marked as writeable with `"is_writeable": true,` and
as executabled with `"is_executable": true`.


```json
        {
            "address": 4416,
            "is_writeable": false,
            "is_executable": true,
            "data": "f30f1efa41574c8d3da32c000041564989d641554989f541544189fc55488d2d942c0000534c29fd4883ec08e88ffeffff48c1fd03741f31db0f1f80000000004c89f24c89ee4489e741ff14df4883c3014839dd75ea4883c4085b5d415c415d415e415fc3"
        }
```
