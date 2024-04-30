// RUN: %wllvm --target=x86_64-unknown-linux-gnu -I%kernel-dir/arch/x86/include -I%kernel-dir/arch/x86/include/generated -I%kernel-dir/arch/x86/include/uapi -I%kernel-dir/arch/x86/include/generated/uapi -I%kernel-dir/include -I%kernel-dir/include/uapi -I%kernel-dir/include/generated/uapi -include %kernel-dir/include/linux/compiler-version.h -include %kernel-dir/include/linux/kconfig.h -include %kernel-dir/include/linux/compiler_types.h -Os -D__KERNEL__ -std=gnu11 -DCC_USING_FENTRY -DMODULE -DKBUILD_BASENAME=seahorn -DKBUILD_MODNAME=seahorn -D__KBUILD_MODNAME=seahorn -fshort-wchar -c %kern-util -o %t-util.o 2> /dev/null
// RUN: %extract-bc %t-util.o
// RUN: %llvm-link %vmlinux-bc %t-util.o.bc -o %t-kernel.bc
// RUN: %wllvm --target=x86_64-unknown-linux-gnu -I%kernel-dir/arch/x86/include -I%kernel-dir/arch/x86/include/generated -I%kernel-dir/arch/x86/include/uapi -I%kernel-dir/arch/x86/include/generated/uapi -I%kernel-dir/include -I%kernel-dir/include/uapi -I%kernel-dir/include/generated/uapi -include %kernel-dir/include/linux/compiler-version.h -include %kernel-dir/include/linux/kconfig.h -include %kernel-dir/include/linux/compiler_types.h -Os -D__KERNEL__ -std=gnu11 -DCC_USING_FENTRY -DMODULE -DKBUILD_BASENAME=seahorn -DKBUILD_MODNAME=seahorn -D__KBUILD_MODNAME=seahorn -fshort-wchar -c %s -o %t.o 2> /dev/null
// RUN: %extract-bc %t.o
// RUN: %llvm-link %t-kernel.bc %t.o.bc -o %t-merged.bc
// RUN: %sea dd --dd-acpi --entry=simple_kboj_main --track=mem --horn-stats --devirt-functions=types --inline "%t-merged.bc"
// CHECK: ^unsat$

#include <linux/kobject.h>
#include <linux/kref.h>
#include <linux/slab.h>

extern void __VERIFIER_error (void);
extern void __VERIFIER_assume (int);
extern void __VERIFIER_assert (bool);
#define sassert(X) (void)((__VERIFIER_assert(X), (X)) || (__VERIFIER_error(), 0))

static void dummy_release(struct kobject *kobj) {}

const struct kobj_type dummy_ktype = {
  .release = dummy_release,
};

int simple_kboj_main(void) {
  struct kobject *kobj = kmalloc(sizeof(*kobj), GFP_KERNEL);
  if (!kobj) {
    return 42;
  }

  sassert(kobj->kset == NULL);
  sassert(kobj->state_initialized == 0);
  sassert(kobj->kref.refcount.refs.counter == 0);

  kobject_init(kobj, &dummy_ktype);

  sassert(kobj->kref.refcount.refs.counter == 1);
  sassert(kobj->state_initialized == 1);
  kobject_get(kobj);
  sassert(kobj->kref.refcount.refs.counter == 2);
  kobject_put(kobj);
  sassert(kobj->kref.refcount.refs.counter == 1);
  return 0;
}
