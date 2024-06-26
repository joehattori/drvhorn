// RUN: set -e
// RUN: %merge %drvhorn-util %kernel-dir/vmlinux.bc %t-kernel.bc %kernel-dir
// RUN: %merge %s %t-kernel.bc %t-merged.bc %kernel-dir
// RUN: %sea kernel --file-operations=tpm_bios_measurements_open_unsat %t-merged.bc | OutputCheck %s
// CHECK: ^unsat$

#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/module.h>
#include <linux/tpm_eventlog.h>

extern void __VERIFIER_error(void);
extern void __VERIFIER_assume(int);
#define sassert(X) (void)((X) || (__VERIFIER_error(), 0))

#define INT_MAX		((int)(~0U >> 1))
#define INT_MIN		(-INT_MAX - 1)

int tpm_bios_measurements_open_unsat(struct inode *inode,
              struct file *file)
{
  int err;
  struct seq_file *seq;
  struct tpm_chip_seqops *chip_seqops;
  const struct seq_operations *seqops;
  struct tpm_chip *chip;
  int counter;

  inode_lock(inode);
  if (!inode->i_private) {
    inode_unlock(inode);
    return -ENODEV;
  }
  chip_seqops = (struct tpm_chip_seqops *)inode->i_private;
  seqops = chip_seqops->seqops;
  chip = chip_seqops->chip;
  get_device(&chip->dev);
  inode_unlock(inode);

  /* now register seq file */
  err = seq_open(file, seqops);
  if (err) {
  	put_device(&chip->dev);
  	return err;
  }

  seq = file->private_data;
  seq->private = chip;
  return 0;
}
