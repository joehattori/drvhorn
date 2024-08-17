#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include "seahorn/Transforms/Kernel/Util.hh"

namespace seahorn {
llvm::StringRef getStructName(llvm::StringRef name) {
  size_t p = name.find('.');
  if (p == llvm::StringRef::npos)
    return name;
  size_t q = name.find('.', p + 1);
  if (q == llvm::StringRef::npos)
    return name;
  return name.substr(0, q);
}

bool equivTypes(const llvm::Type *t1, const llvm::Type *t2) {
  if (t1 == t2)
    return true;
  const llvm::StructType *st1 = llvm::dyn_cast<llvm::StructType>(t1);
  const llvm::StructType *st2 = llvm::dyn_cast<llvm::StructType>(t2);
  if (!st1 || !st2 || !st1->hasName() || !st2->hasName())
    return false;
  llvm::StringRef p1 = getStructName(st1->getName());
  llvm::StringRef p2 = getStructName(st2->getName());
  return p1 == p2;
}

const llvm::Function *extractCalledFunction(const llvm::CallInst *call) {
  return llvm::dyn_cast<llvm::Function>(
      call->getCalledOperand()->stripPointerCasts());
}

llvm::Function *extractCalledFunction(llvm::CallInst *call) {
  return llvm::dyn_cast<llvm::Function>(
      call->getCalledOperand()->stripPointerCasts());
}

const llvm::Function *extractCalledFunction(const llvm::CallInst &call) {
  return llvm::dyn_cast<llvm::Function>(
      call.getCalledOperand()->stripPointerCasts());
}

llvm::Function *extractCalledFunction(llvm::CallInst &call) {
  return llvm::dyn_cast<llvm::Function>(
      call.getCalledOperand()->stripPointerCasts());
}

static void collectCallUser(llvm::User *user,
                            llvm::SmallVector<llvm::CallInst *, 16> &res,
                            llvm::DenseSet<llvm::User *> &visited) {
  if (!visited.insert(user).second)
    return;
  if (llvm::isa<llvm::Instruction>(user)) {
    if (llvm::CallInst *call = llvm::dyn_cast<llvm::CallInst>(user))
      res.push_back(call);
  } else {
    for (llvm::User *user : user->users()) {
      collectCallUser(user, res, visited);
    }
  }
}

static void collectCallUser(const llvm::User *user,
                            llvm::SmallVector<const llvm::CallInst *, 16> &res,
                            llvm::DenseSet<const llvm::User *> &visited) {
  if (!visited.insert(user).second)
    return;
  if (llvm::isa<llvm::Instruction>(user)) {
    if (const llvm::CallInst *call = llvm::dyn_cast<llvm::CallInst>(user))
      res.push_back(call);
  } else {
    for (const llvm::User *user : user->users()) {
      collectCallUser(user, res, visited);
    }
  }
}

llvm::SmallVector<llvm::CallInst *, 16> getCalls(llvm::Function *fn) {
  llvm::SmallVector<llvm::CallInst *, 16> res;
  llvm::DenseSet<llvm::User *> visited;
  collectCallUser(fn, res, visited);
  return res;
}

llvm::SmallVector<const llvm::CallInst *, 16>
getCalls(const llvm::Function *fn) {
  llvm::SmallVector<const llvm::CallInst *, 16> res;
  llvm::DenseSet<const llvm::User *> visited;
  collectCallUser(fn, res, visited);
  return res;
}

llvm::Optional<size_t> getEmbeddedDeviceIndex(const llvm::StructType *s) {
  const llvm::StructType *deviceType =
      llvm::StructType::getTypeByName(s->getContext(), "struct.device");
  for (size_t i = 0; i < s->getNumElements(); i++) {
    if (equivTypes(s->getElementType(i), deviceType))
      return i;
  }
  return llvm::None;
}

llvm::SmallVector<llvm::GlobalVariable *> getKobjects(llvm::Module &m) {
  llvm::SmallVector<llvm::GlobalVariable *> res;
  if (llvm::GlobalVariable *g = m.getGlobalVariable("device_node_kobject")) {
    res.push_back(g);
  }
  for (llvm::GlobalVariable &g : m.globals()) {
    if (g.getName().startswith("drvhorn.kobject."))
      res.push_back(&g);
  }
  return res;
}
} // namespace seahorn
