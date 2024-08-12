#include "llvm/Analysis/CallGraph.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"

#include <set>
#include <vector>

using namespace llvm;

namespace seahorn {

class Debug : public ModulePass {
public:
  static char ID;

  Debug() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    unsigned int counter = 0;
    errs() << "DEBUG\n";
    M.setModuleInlineAsm("");
    M.dump();
    errs() << "\n";
    // for (StringRef name : {
    //          "pmu",
    //          "schedule",
    //      }) {
    //   printUses(M, name);
    // }

    // for (StringRef name : {
    //          "kobject_put",
    //      }) {
    //   GlobalValue *f = M.getNamedValue(name);
    //   if (!f) {
    //     errs() << "no such function or global var " << name.str() << "\n";
    //     continue;
    //   }
    //   std::set<StringRef> s;
    //   aggregateUsers(f, s, name);
    //   for (StringRef name : s) {
    //     errs() << "name " << name << "\n";
    //   }
    // }

    {
      unsigned c = 0;
      for (auto &g : M.globals()) {
        if (g.hasName()) {
          errs() << "global var: " << g.getName() << '\n';
          c++;
        }
      }
      errs() << "global vars " << c << '\n';
    }
    for (Function &F : M) {
      errs() << "Func " << F.getName().str() << "\n";
      if (F.isDeclaration() || !F.hasName())
        continue;
      for (Instruction &inst : instructions(F)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (InlineAsm *inlineAsm =
                  dyn_cast<InlineAsm>(call->getCalledOperand())) {
            if (counter < 0) {
              StringRef name = F.getName();
              errs() << "In func " << name.str() << "\n";
              errs() << "asm: " << inlineAsm->getAsmString() << "\n";
              errs() << "constraints " << inlineAsm->getConstraintString()
                     << "\n";
            }
            counter++;
          }
        }
      }
    }
    errs() << "Total number of inline asm instructions: " << counter << "\n";
    verify(M);
    return false;
  }

  virtual StringRef getPassName() const override { return "KernelDebug"; }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<CallGraphWrapperPass>();
    AU.addPreserved<CallGraphWrapperPass>();
  }

private:
  std::map<StringRef, std::set<StringRef>> getCallers(Module &M) {
    std::map<StringRef, std::set<StringRef>> callers;
    for (Function &F : M) {
      if (F.isDeclaration() || !F.hasName())
        continue;
      for (User *U : F.users()) {
        if (Instruction *I = dyn_cast<Instruction>(U)) {
          if (Function *caller = I->getFunction()) {
            callers[F.getName()].insert(caller->getName());
          }
        }
      }
    }
    return callers;
  }

  void printUses(Module &M, StringRef name) {
    GlobalValue *f = M.getNamedValue(name);
    if (!f) {
      errs() << "no such function or global var " << name.str() << "\n";
      return;
    }
    errs() << "uses of " << name.str() << "\n";
    int count = 0;
    for (User *use : f->users()) {
      printUseBelong(use);
      errs() << "\n";
      // use->dump();
      count++;
    }
    if (!count) {
      errs() << "is droppable " << f->isDiscardableIfUnused() << '\n';
      errs() << "linkage " << f->getLinkage() << '\n';
      errs() << "isdecl " << f->isDeclaration() << '\n';
    }
    errs() << "use count: " << count << " droppable "
           << f->isDiscardableIfUnused() << "\n\n";
  }

  bool printUseBelong(User *use) {
    if (Instruction *inst = dyn_cast<Instruction>(use)) {
      errs() << "inst in func: " << inst->getFunction()->getName().str() << ' ';
      return true;
    } else if (GlobalVariable *g = dyn_cast<GlobalVariable>(use)) {
      errs() << "global var: " << g->getName() << ' ';
      return true;
    } else if (Constant *c = dyn_cast<Constant>(use)) {
      for (User *user : c->users()) {
        if (printUseBelong(user))
          return true;
      }
      errs() << "other constant ";
      return false;
    } else if (Operator *op = dyn_cast<Operator>(use)) {
      for (User *user : op->users()) {
        if (printUseBelong(user)) {
          return true;
        }
      }
      errs() << "other op ";
      return false;
    } else {
      errs() << "simple other ";
      return false;
    }
  }

  void aggregateUsers(User *user, std::set<StringRef> &s, StringRef prev) {
    StringRef name = "";
    if (Instruction *inst = dyn_cast<Instruction>(user)) {
      name = inst->getFunction()->getName();
      user = inst->getFunction();
    } else if (GlobalVariable *g = dyn_cast<GlobalVariable>(user)) {
      name = g->getName();
    }
    bool skip = false;
    if (!name.empty()) {
      skip = !s.insert(name).second;
      if (!skip) {
        errs() << "inserting " << name << " because of " << prev << "\n";
      }
    }
    if (skip)
      return;
    StringRef newPrev = prev;
    if (!name.empty()) {
      newPrev = name;
    }
    for (User *u : user->users())
      aggregateUsers(u, s, newPrev);
  }

  void verify(Module &M) {
    if (verifyModule(M, &errs())) {
      for (Function &f : M) {
        if (verifyFunction(f, &errs())) {
          errs() << "Function " << f.getName() << " verification failed\n";
          f.dump();
        }
      }
      errs() << "Module verification failed\n";
    } else {
      errs() << "Module verification Ok\n";
    }
  }
};

char Debug::ID = 0;

Pass *createKernelDebugPass() { return new Debug(); };
} // namespace seahorn
