#include <asm/pgtable_types.h>
#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/mm_types.h>
#include <linux/nodemask.h>
#include <linux/types.h>
#include <linux/of.h>
#include <linux/device/class.h>
#include <linux/slab.h>
#include <linux/phy.h>
#include <base/base.h>

extern _Bool nd_bool();
extern char nd_char();
extern int nd_int();
extern unsigned nd_uint();
extern size_t nd_size();
extern void __VERIFIER_error(void);
extern void __VERIFIER_assume(int);
#define sassert(X) (void)((X) || (__VERIFIER_error(), 0))

void __DRVHORN_memcpy(char *dst, char *src, unsigned long long n,
                      _Bool is_volatile) {
  unsigned long long i;
  for (i = 0; i < n; i++)
    dst[i] = src[i];
}

char *__DRVHORN_strcpy(char *dest, const char *src) {
  int i = 0;
  while (src[i]) {
    dest[i] = src[i];
    i++;
  }
  dest[i] = '\0';
  return dest;
}

char *__DRVHORN_strncpy(char *dest, const char *src, unsigned long n) {
  int i = 0;
  while (src[i] && i < n) {
    dest[i] = src[i];
    i++;
  }
  dest[i] = '\0';
  return dest;
}

int __DRVHORN_strcmp(const char *s1, const char *s2) {
  int i = 0;
  while (s1[i] && s2[i] && s1[i] == s2[i])
    i++;
  return s1[i] - s2[i];
}

int __DRVHORN_strncmp(const char *s1, const char *s2, unsigned long n) {
  int i = 0;
  while (s1[i] && s2[i] && s1[i] == s2[i] && (unsigned long)i < n)
    i++;
  return s1[i] - s2[i];
}

unsigned long __DRVHORN_strlen(const char *s) {
  unsigned long i = 0;
  while (s[i])
    i++;
  return i;
}

unsigned long __DRVHORN_strnlen(const char *s, unsigned long count) {
  unsigned long i = 0;
  while (s[i] && i < count)
    i++;
  return i;
}

u64 __DRVHORN_util_read_u64(u8 *addr) { return *(u64 *)addr; }
u32 __DRVHORN_util_read_u32(u8 *addr) { return *(u32 *)addr; }
u16 __DRVHORN_util_read_u16(u8 *addr) { return *(u16 *)addr; }
u8 __DRVHORN_util_read_u8(u8 *addr) { return *addr; }

void __DRVHORN_update_index(long long int index, long long int *target_index) {
  if (nd_bool())
    *target_index = index;
}

static void klist_children_get(struct klist_node *n)
{
  struct device_private *p = to_device_private_parent(n);
  struct device *dev = p->device;

  get_device(dev);
}

static void klist_children_put(struct klist_node *n)
{
  struct device_private *p = to_device_private_parent(n);
  struct device *dev = p->device;

  put_device(dev);
}

static int __DRVHORN_device_private_init(struct device *dev)
{
  dev->p = kzalloc(sizeof(*dev->p), GFP_KERNEL);
  if (!dev->p)
    return -ENOMEM;
  dev->p->device = dev;
  klist_init(&dev->p->klist_children, klist_children_get,
       klist_children_put);
  INIT_LIST_HEAD(&dev->p->deferred_probe);
  return 0;
}
