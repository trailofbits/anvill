/*
 * Copyright (c) 2021 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <anvill/Analysis/CrossReferenceResolver.h>
#include <anvill/ITransformationErrorManager.h>
#include <anvill/Lifters/Options.h>
#include <anvill/Lifters/ValueLifter.h>
#include <llvm/IR/PassManager.h>

namespace llvm {
class Function;
}  // namespace llvm
namespace anvill {

class EntityLifter;

// When lifting conditional control-flow, we end up with the following pattern:
//
//        %25 = icmp eq i8 %24, 0
//        %26 = select i1 %25, i64 TAKEN_PC, i64 NOT_TAKEN_PC
//        br i1 %25, label %27, label %34
//
//        27:
//        ... use of %26
//
//        34:
//        ... use of %26
//
// This function pass transforms the above pattern into the following:
//
//        %25 = icmp eq i8 %24, 0
//        br i1 %25, label %27, label %34
//
//        27:
//        ... use of TAKEN_PC
//
//        34:
//        ... use of NOT_TAKEN_PC
//
// When this happens, we're better able to fold cross-references at the targets
// of conditional branches.
void AddSinkSelectionsIntoBranchTargets(
    llvm::FunctionPassManager &fpm, ITransformationErrorManager &error_manager);

// Remill semantics sometimes contain compiler barriers (empty inline assembly
// statements), especially related to floating point code (i.e. preventing
// re-ordering of floating point operations so that we can capture the flags).
// This pass eliminates those empty inline assembly statements.
void AddRemoveCompilerBarriers(llvm::FunctionPassManager &fpm);

// Analyze `func` and determine if the function stores the return value of
// the `llvm.returnaddress` intrinsic into an `alloca` (presumed to be the
// stack frame). If so, split the stack frame into three separate `alloca`s:
//
//    1) One for every up to but not including the location where the return
//       address is stored.
//    2) One for the return address itself.
//    3) One for everything else.
//
// The `arch` is consulted to determine the default stack growth direction,
// which informs the behavior of the function in the presence of multiple
// stores of the return address into a stack frame.
//
// Anvill's approach to stack frame recovery is slightly atypical: if a
// function's return address is stored on the stack, or if a function's
// arguments are stored on the stack (typical in x86), then these are all
// considered to be part of the stack frame. In that way, the stack frame
// actually extends into what is typically thought of as the caller's stack
// frame. This approach is very convenient, but comes at the cost of having
// to do this particular transformation in order to recover more typical stack
// frame structures.
void AddSplitStackFrameAtReturnAddress(
    llvm::FunctionPassManager &fpm, ITransformationErrorManager &error_manager);

// Remove unused calls to floating point classification functions. Calls to
// these functions are present in a bunch of FPU-related instruction semantics
// functions. It's frequently the case that instructions don't actually care
// about the FPU state, though. In these cases, we won't observe the return
// values of these classification functions being used. However, LLVM can't
// eliminate the calls to these functions on its own because they are not
// "pure" functions.
//
// NOTE(pag): This pass must be applied before any kind of renaming of lifted
//            functions is performed, so that we don't accidentally remove
//            calls to classification functions present in the target binary.
void AddRemoveUnusedFPClassificationCalls(llvm::FunctionPassManager &fpm);

// Lowers the `__remill_read_memory_NN`, `__remill_write_memory_NN`, and the
// various atomic read-modify-write variants into LLVM loads and stores.
void AddLowerRemillMemoryAccessIntrinsics(llvm::FunctionPassManager &fpm);

// Type information from prior lifting efforts, or from front-end tools
// (e.g. Binary Ninja) is plumbed through the system by way of calls to // intrinsic functions such as `__anvill_type<blah>`. These function calls
// don't interfere (too much) with optimizations, and they also survive
// optimizations. In general, the key role that they serve is to enable us to
// propagate through pointer type information at an instruction/register
// granularity.
//
// These function calls need to be removed/lowered into `inttoptr` or `bitcast`
// instructions.
void AddLowerTypeHintIntrinsics(llvm::FunctionPassManager &fpm);

// Anvill-lifted bitcode operates at a very low level, swapping between integer
// and pointer representations. It is typically for just-lifted bitcode to
// perform integer arithmetic on addresses, then cast those integers into
// pointers in order to do a `load` or `store`. This happens because the bitcode
// we get from Remill uses memory access intrinsics, which abstract over the
// target program's address space and model memory loads/stores in terms of
// intrinsic function calls operating on integer addresses. When these intrinsic
// calls are lowered into `load` and `store` instructions by
// `LowerRemillMemoryAccessIntrinsics`, we are left with a mixed bag in integer
// arithmetic and then `inttoptr` casts.
//
// Ideally, we want to comprehensively brighten all integer operations that
// produce pointers into pointer operations. For example, integer arithmetic
// should instead become `getelementptr` instructions, where possible, which
// model pointer arithmetic at a higher level.
//
// This function attempts to apply a battery of pattern-based transforms to
// brighten integer operations into pointer operations.
void AddBrightenPointerOperations(llvm::FunctionPassManager &fpm,
                                  unsigned max_gas = 250);

// Transforms the bitcode to eliminate calls to `__remill_function_return`,
// where appropriate. This will not succeed for all architectures, but is
// likely to always succeed for x86(-64) and aarch64, due to their support
// for the `llvm.addressofreturnaddress` intrinsic.
//
// When we lift bitcode, we represent the control-flow transfer semantics of
// function returns with calls to `__remill_function_return`. This is another
// three-argument Remill function, where the second argument is the program
// counter. We're particularly interested in observing this program counter
// value, as it can tell us if this function respects normal return conventions
// (i.e. returns to its return address) or not. The way we try to observe this
// is by inspecting the program counter argument, and seeing if it is
// `__anvill_ra` or the (casted) value returned from the `llvm.returnaddress`
// intrinsic.
//
// When we match the expected pattern, we can eliminate calls to
// `__remill_function_return`. If we don't match the pattern, then it suggests
// that it is possible that the function alters its return address, or that
// something is preventing our analysis from deducing that the return address
// reaches the `__remill_function_return` call's program counter argument.
//
// On x86(-64) and AArch64, we can use the `llvm.addressofreturnaddress` to
// update the return address in place when we fail to match the pattern,
// thereby letting us eliminate the call to `__remill_function_return`.
//
// NOTE(pag): This pass should be applied as late as possible, as the call to
//            `__remill_function_return` depends upon the memory pointer.
void AddRemoveRemillFunctionReturns(llvm::FunctionPassManager &fpm,
                                    const EntityLifter &lifter);

// This function pass makes use of the `__anvill_sp` usages to create an
// `llvm::StructType` that acts as a stack frame. This initial stack frame
// is an array of bytes. The initial purpose of this stack frame is to observe
// uses of possibly uninitialized bytes in the stack (via `kSymbolic` in
// `StackFrameStructureInitializationProcedure` in `options`), to enable
// baseline scalar replacement of aggregates (SROA), and if that pass fails
// to eliminate the stack frame, then to enable splitting of the stack from
// into components (see `CreateSplitStackFrameAtReturnAddress`) such that
// SROA can apply to the arguments and return address components.
void AddRecoverStackFrameInformation(llvm::FunctionPassManager &fpm,
                                     ITransformationErrorManager &error_manager,
                                     const LifterOptions &options);

// Anvill-lifted code is full of references to constant expressions related
// to `__anvill_pc`. These constant expressions exist to "taint" values as
// being possibly related to the program counter, and thus likely being
// pointers.
//
// This goal of this pass is to opportunistically identify uses of values
// that are related to the program counter, and likely to be references to
// other entitities. We say opportunistic because that pass is not guaranteed
// to replace all such references, and will in fact leave references around
// for later passes to benefit from.
void AddRecoverEntityUseInformation(llvm::FunctionPassManager &fpm,
                                    ITransformationErrorManager &error_manager,
                                    const EntityLifter &lifter);

// Some machine code instructions explicitly introduce undefined values /
// behavior. Often, this is a result of the CPUs of different steppings of
// an ISA producing different results for specific registers. For example,
// some instructions leave the value of specific arithmetic flags instructions
// in an undefined state.
//
// Remill models these situations using opaque function calls, i.e. an
// undefined value is produced via a call to something like
// `__remill_undefined_8`, which represents an 8-bit undefined value. We want
// to lower these to `undef` values in LLVM; however, we don't want to do this
// too early, otherwise the "undefinedness" can spread and possibly get out
// of control.
//
// This pass exists to do the lowering to `undef` values, and should be run
// as late as possible.
void AddLowerRemillUndefinedIntrinsics(llvm::FunctionPassManager &fpm);

// This function pass will attempt to fold the following instruction
// combinations:
// {SelectInst, PHINode}/{BinaryOperator, CastInst, GetElementPtrInst}
void AddInstructionFolderPass(llvm::FunctionPassManager &fpm,
                              ITransformationErrorManager &error_manager);

// Removes trivial PHI and select nodes. These are PHI and select nodes whose
// incoming values or true/false values match. This can happen as a result of
// the instruction folding pass that hoists and folds values up through selects
// and PHI nodes, followed by the select sinking pass, which pushes values down.
void AddRemoveTrivialPhisAndSelects(llvm::FunctionPassManager &fpm);

// The pass transforms bitcode to replace the calls to `__remill_jump` into
// `__remill_function_return` if a value returned by `llvm.returnaddress`, or
// casted from `__anvill_ra`, reaches to its `PC` argument.
//
// The transform is written to fix the bitcode generated for aarch32 architecture
// where multiple instructions semantic can be used to return from the function
// and they might be categorized as (conditional/unconditional) indirect jumps
//
// It identifies the possible cases where a return instruction is lifted as
// indirect jump and fixes the intrinsics for them.

// NOTE: The pass should be run as late as possible in the list but before
// `RemoveRemillFunctionReturns` transform
void AddTransformRemillJumpIntrinsics(llvm::FunctionPassManager &fpm,
                                      const EntityLifter &lifter);

// Finds values in the form of:
// %cmp = icmp eq val1, val2
// %n = xor %cmp, 1
// (optional):
// %br %cmp, d1, d2
// and converts it to :
// %cmp = icmp ne val1, val2
// %n = %cmp
// %br %cmp, d2, d1
//
// This happens often enough in lifted code due to bit shift ops, and the code
// with xors is more difficult to analyze and for a human to read
// This pass should only work on boolean values, and handle when those are used
// in Branches and Selects
void AddConvertXorToCmp(llvm::FunctionPassManager &fpm);

// Removes calls to `__remill_delay_slot_begin` and `__remill_delay_slot_end`.
// These calls surround the lifted versions of delayed instructions, to signal
// their location in the bitcode.
void AddRemoveDelaySlotIntrinsics(llvm::FunctionPassManager &fpm);

// Removes calls to `__remill_error`.
void AddRemoveErrorIntrinsics(llvm::FunctionPassManager &fpm);

}  // namespace anvill
