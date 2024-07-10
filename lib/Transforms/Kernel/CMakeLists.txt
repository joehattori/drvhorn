add_llvm_library(SeaTransformsKernel DISABLE_LLVM_LINK_LLVM_DYLIB
  Acpi.cc
  FileOperations.cc
  KernelSetup.cc
  Debug.cc
  SlimDown.cc
  Platform.cc
  DeviceTree.cc
  )
