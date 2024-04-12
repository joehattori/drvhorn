add_llvm_library(SeaTransformsKernel DISABLE_LLVM_LINK_LLVM_DYLIB
  Acpi.cc
  KernelSetup.cc
  Debug.cc
  RemoveUnnecessaryFunctions.cc
  )
