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

namespace llvm {
class DataLayout;
class Module;
class Value;
}  // namespace llvm
namespace anvill {

// Returns `true` if it looks like `val` is the program counter.
bool IsProgramCounter(llvm::Module *module, llvm::Value *val);

// Returns `true` if it looks like `val` is the stack counter.
bool IsStackPointer(llvm::Module *module, llvm::Value *val);

// Returns `true` if it looks like `val` is the return address.
bool IsReturnAddress(llvm::Module *module, llvm::Value *val);

// Returns `true` if it looks like `val` is derived from a symbolic stack
// pointer representation.
bool IsRelatedToStackPointer(llvm::Module *module, llvm::Value *val);

// Returns `true` if `val` looks like it is backed by a definition, and thus can
// be the aliasee of an `llvm::GlobalAlias`.
bool CanBeAliased(llvm::Value *val);

}  // namespace anvill
