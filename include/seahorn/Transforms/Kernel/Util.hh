#pragma once

#include "llvm/IR/Instructions.h"

namespace seahorn {
llvm::StringRef getStructName(llvm::StringRef name);
bool equivTypes(const llvm::Type *t1, const llvm::Type *t2);
const llvm::Function *extractCalledFunction(const llvm::CallInst *call);
llvm::Function *extractCalledFunction(llvm::CallInst *call);
const llvm::Function *extractCalledFunction(const llvm::CallInst &call);
llvm::Function *extractCalledFunction(llvm::CallInst &call);
llvm::SmallVector<llvm::CallInst *, 16> getCalls(llvm::Function *fn);
llvm::SmallVector<const llvm::CallInst *, 16>
getCalls(const llvm::Function *fn);
llvm::Function *getOrCreateNdIntFn(llvm::Module &m, unsigned);
llvm::Optional<llvm::SmallVector<unsigned>>
indicesToStruct(const llvm::StructType *s, const llvm::Type *target);
bool embedsStruct(const llvm::StructType *s, const llvm::Type *target);
} // namespace seahorn
