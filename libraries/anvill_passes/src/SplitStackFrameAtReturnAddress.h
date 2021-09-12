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

//
// The main goal of this pass is to isolate the return address value
// saved on the stack frame in its own structure, so that additional
// function passes can more easily eliminate clean up the code and
// eliminate unneeded structures from the stack frame.
//
// The following is an example scenario
//
//     int add(int *a, int *b) {
//       return *a + *b;
//     }
//
//     int main(int argc, char **) {
//       int x = argc;
//       return add(&x, &x);
//     }
//
// The stack frame may look like this:
//
//     struct StackFrame final {
//       int argc;
//       void *ret_addr_of_main;
//       int x;
//     };
//
// Passing the `x` pointer to the call causes LLVM to not be able to rule
// out the possibility that the `add` function may in fact decide to access
// other members in the stack frame (like StackFrame::argc). This prevents
// further optimizations to simplify the code.
//
// In order to fix this problem, this function pass splits the StackFrame
// type while also updating all its usages throughout the code.
//
// Here's how this example scenario is handled:
//
//     struct StackFrame_part0 final {
//       int argc;
//     };
//
//     struct StackFrame_part1 final {
//       void *ret_addr_of_main;
//     };
//
//     struct StackFrame_part2 final {
//       int x;
//     };
//

#pragma once

#include "BaseFunctionPass.h"

namespace anvill {

// Function pass outcome
enum class StackFrameSplitErrorCode {
  // The stack frame type was not found
  StackFrameTypeNotFound,

  // The stack frame allocation instruction was not found
  StackFrameAllocaInstNotFound,

  // Unexpected stack frame type format
  UnexpectedStackFrameTypeFormat,

  // Unexpected stack frame usage, causing the instruction tracking to fail
  UnexpectedStackFrameUsage,

  // The post-transformation verification step has failed
  TransformationFailed,

  // An unexpected, internal error
  InternalError,

  // A type could not be defined due to an existing type with
  // the same name
  TypeConflict,

  // The function cleanup has failed; some of the GEP instructions could
  // not be erased since they still had uses that were not replaced
  // correctly
  FunctionCleanupError,

  // An error has occurred while the stack frame was split and the
  // resulting size is not correct
  InvalidStackFrameSize,
};

// A Result<> object where the value is not tracked
using SuccessOrStackFrameSplitErrorCode =
    Result<std::monostate, StackFrameSplitErrorCode>;

// Contains the necessary information to perform the stack splitting operation
struct FunctionStackAnalysis final {
  // Describes a GEP instruction
  struct GEPInstruction final {
    // The original instruction
    llvm::GetElementPtrInst *instr{nullptr};

    // The offset into the structure
    std::int64_t offset{};
  };

  // A stack frame part
  struct StackFramePart final {
    // Start offset
    std::int64_t start_offset{};

    // End offset
    std::int64_t end_offset{};

    // Part size
    std::int64_t size{};
  };

  // The stack frame type
  llvm::StructType *stack_frame_type{nullptr};

  // Stack frame size
  std::size_t stack_frame_size{};

  // The instruction allocating the stack frame
  llvm::AllocaInst *stack_frame_alloca{nullptr};

  // The size of a pointer
  std::size_t pointer_size{};

  // A list of GEP instructions that are operating on the
  // stack frame
  std::vector<GEPInstruction> gep_instr_list;

  // A list of new stack frame parts
  std::vector<StackFramePart> stack_frame_parts;
};

// Splits the stack frame type of the given function, isolating the
// llvm.returnaddress (if present) in its own StructType to allow for
// further optimization passes to better simplify/eliminate stack
// accesses.
class SplitStackFrameAtReturnAddress final
    : public BaseFunctionPass<SplitStackFrameAtReturnAddress> {

 public:
  // Creates a new SplitStackFrameAtReturnAddress object
  static void Add(llvm::FunctionPassManager &fpm,
                  ITransformationErrorManager &error_manager);

  // Function pass entry point
  llvm::PreservedAnalyses Run(llvm::Function &function);

  // Analyses the function to determine the necessary steps to split
  // the function's stack frame
  static Result<FunctionStackAnalysis, StackFrameSplitErrorCode>
  AnalyzeFunction(llvm::Function &function);

  // Updates the function to split the stack frame usage around the
  // return address value
  static SuccessOrStackFrameSplitErrorCode
  SplitStackFrame(llvm::Function &function,
                  const FunctionStackAnalysis &stack_analysis);

  // Executes the function pass logic
  Result<bool, StackFrameSplitErrorCode> execute(llvm::Function &function);

  // Returns the name of the stack frame type for the given function
  static std::string
  GetFunctionStackFrameTypeName(const llvm::Function &function);

  // Returns the stack frame type for the given function
  static Result<llvm::StructType *, StackFrameSplitErrorCode>
  GetFunctionStackFrameType(const llvm::Function &function);

  // Generates a new name for a stack frame part
  static std::string
  GenerateStackFramePartTypeName(const llvm::Function &function,
                                 std::size_t part_number);

  virtual ~SplitStackFrameAtReturnAddress(void) override = default;

 private:
  SplitStackFrameAtReturnAddress(ITransformationErrorManager &error_manager);
};

}  // namespace anvill
