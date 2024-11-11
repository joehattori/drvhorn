add_llvm_library(SeaTransformsKernel DISABLE_LLVM_LINK_LLVM_DYLIB
  Acpi.cc
  FileOperations.cc
  KernelSetup.cc
  I2CDriver.cc
  Platform.cc

  Debug.cc
  SlimDown.cc
  Device.cc
  Devm.cc
  Util.cc
  NondetMalloc.cc
  IntoBinary.cc
  AssumeNonNull.cc
  DsaSwitchOps.cc
  InitGlobalKrefs.cc
  SpecificFunction.cc
  ListOps.cc
  HandleInlineAsm.cc
  AssertKrefs.cc
  )
