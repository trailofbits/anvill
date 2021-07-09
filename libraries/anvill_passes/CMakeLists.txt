#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_library(anvill_passes STATIC
  include/anvill/Transforms.h

  src/LowerRemillMemoryAccessIntrinsics.cpp
  src/LowerRemillUndefinedIntrinsics.cpp
  src/LowerTypeHintIntrinsics.cpp
  src/RemoveCompilerBarriers.cpp
  src/RemoveDelaySlotIntrinsics.cpp
  src/RemoveErrorIntrinsics.cpp
  src/RemoveRemillFunctionReturns.cpp
  src/RemoveTrivialPhisAndSelects.cpp
  src/RemoveUnusedFPClassificationCalls.cpp

  src/SinkSelectionsIntoBranchTargets.h
  src/SinkSelectionsIntoBranchTargets.cpp

  src/SplitStackFrameAtReturnAddress.h
  src/SplitStackFrameAtReturnAddress.cpp

  src/BrightenPointerOperations.h
  src/BrightenPointerOperations.cpp
  
  src/RecoverEntityUseInformation.h
  src/RecoverEntityUseInformation.cpp

  src/RecoverStackFrameInformation.h
  src/RecoverStackFrameInformation.cpp

  src/InstructionFolderPass.h
  src/InstructionFolderPass.cpp

  src/BaseFunctionPass.h

  src/Utils.h
  src/Utils.cpp

  include/anvill/ITransformationErrorManager.h
  src/TransformationErrorManager.h
  src/TransformationErrorManager.cpp
  src/TransformRemillJumpIntrinsics.cpp

  src/ConvertXorToCmp.cpp
)

target_include_directories(anvill_passes PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(anvill_passes PUBLIC
  remill_settings
  anvill
)

target_compile_definitions(anvill_passes PRIVATE
  "LLVM_MAJOR_VERSION=${LLVM_MAJOR_VERSION}"
)

addMagicEnumLibrary(anvill_passes)

if(ANVILL_ENABLE_TESTS)
  add_subdirectory("tests")
endif()

if(ANVILL_ENABLE_INSTALL_TARGET)
  install(
    TARGETS
      anvill_passes

    EXPORT
      anvillTargets

    LIBRARY DESTINATION
      lib

    ARCHIVE DESTINATION
      lib

    INCLUDES DESTINATION
      include

    PUBLIC_HEADER DESTINATION
      "${CMAKE_INSTALL_INCLUDEDIR}/anvill"
  )
endif()
