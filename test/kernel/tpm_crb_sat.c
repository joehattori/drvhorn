// RUN: %wllvm --target=x86_64-unknown-linux-gnu -I%kernel-dir/arch/x86/include -I%kernel-dir/arch/x86/include/generated -I%kernel-dir/arch/x86/include/uapi -I%kernel-dir/arch/x86/include/generated/uapi -I%kernel-dir/include -I%kernel-dir/include/uapi -I%kernel-dir/include/generated/uapi -include %kernel-dir/include/linux/compiler-version.h -include %kernel-dir/include/linux/kconfig.h -include %kernel-dir/include/linux/compiler_types.h -Os -D__KERNEL__ -std=gnu11 -DCC_USING_FENTRY -DMODULE -DKBUILD_BASENAME=seahorn -DKBUILD_MODNAME=seahorn -D__KBUILD_MODNAME=seahorn -fshort-wchar -c %kern-util -o %t-util.o 2> /dev/null
// RUN: %extract-bc %t-util.o
// RUN: %llvm-link %vmlinux-bc %t-util.o.bc -o %t-kernel.bc
// RUN: %sea kernel --acpi-driver=crb_acpi_driver --track=mem --horn-stats --externalize-addr-taken-functions --devirt-functions=types --inline "%t-kernel.bc" | OutputCheck %s
// CHECK: ^sat$
