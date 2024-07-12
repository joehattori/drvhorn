#include <asm/pgtable_types.h>
#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/mm_types.h>
#include <linux/nodemask.h>
#include <linux/types.h>
#include <linux/of.h>
#include <linux/device/class.h>
#include <base/base.h>

extern _Bool nd_bool();
extern char nd_char();
extern int nd_int();
extern void __VERIFIER_error(void);
extern void __VERIFIER_assume(int);
#define sassert(X) (void)((X) || (__VERIFIER_error(), 0))

void __DRVHORN_memcpy(char *dst, char *src, unsigned long long n,
                      _Bool is_volatile) {
  unsigned long long i;
  for (i = 0; i < n; i++)
    dst[i] = src[i];
}

extern void *malloc(unsigned long size);
extern void *zalloc(unsigned long size);
void *__DRVHORN_malloc(unsigned long size, unsigned flags) {
  if (nd_bool())
    return 0;
  // malloc() will be replaced by alloca in the PromoteMalloc pass.
  if (flags & 0x100u)
    return zalloc(size);
  else
    return malloc(size);
}

void *__attribute__((always_inline))
__DRVHORN___kmalloc(unsigned long size, unsigned flags) {
  return __DRVHORN_malloc(size, flags);
}

void *__attribute__((always_inline))
__DRVHORN___kmalloc_node(unsigned long size, unsigned flags, int node) {
  return __DRVHORN_malloc(size, flags);
}

void *__attribute__((always_inline))
__DRVHORN___kmalloc_node_track_caller(unsigned long size, unsigned flags,
                                      int node, unsigned long caller) {
  return __DRVHORN_malloc(size, flags);
}

void *__attribute__((always_inline))
__DRVHORN_kmalloc_large(unsigned long size, unsigned flags) {
  return __DRVHORN_malloc(size, flags);
}

void *__attribute__((always_inline))
__DRVHORN_kmalloc_large_node(unsigned long size, unsigned flags, int node) {
  return __DRVHORN_malloc(size, flags);
}

void *__attribute__((always_inline))
__DRVHORN___vmalloc_node_range(unsigned long size, unsigned long align,
                               unsigned long start, unsigned long end,
                               unsigned int gfp_mask, pgprot_t prot,
                               unsigned long vm_flags, int node,
                               const void *caller) {
  return __DRVHORN_malloc(size, 0);
}

void *__attribute__((always_inline))
__DRVHORN_pcpu_alloc(unsigned long size, unsigned long align, _Bool reserved,
                     unsigned flags) {
  return __DRVHORN_malloc(size, flags);
}

void *__attribute__((always_inline))
__DRVHORN_slob_alloc(unsigned long size, unsigned flags, int align, int node) {
  return __DRVHORN_malloc(size, flags);
}

void *__DRVHORN___ioremap_caller(unsigned long long addr, unsigned long size,
                                 int prot, void *caller, _Bool d) {
  return __DRVHORN_malloc(size, 0);
}

void *__DRVHORN___early_ioremap(resource_size_t phys_addr, unsigned long size,
                                pgprot_t prot) {
  return __DRVHORN_malloc(size, 0);
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

struct page *__DRVHORN___alloc_pages() {
  return nd_bool() ? malloc(sizeof(struct page)) : 0;
}

u64 __DRVHORN_util_read_u64(u8 *addr) { return *(u64 *)addr; }
u32 __DRVHORN_util_read_u32(u8 *addr) { return *(u32 *)addr; }
u16 __DRVHORN_util_read_u16(u8 *addr) { return *(u16 *)addr; }
u8 __DRVHORN_util_read_u8(u8 *addr) { return *addr; }

int __DRVHORN_util_get_kobject_count(const struct kobject *kobj) {
  return kobj->kref.refcount.refs.counter;
}

int __DRVHORN_util_get_device_counter(const struct device *dev) {
  return __DRVHORN_util_get_kobject_count(&dev->kobj);
}

static void __DRVHORN_kobject_release(struct kobject *kobj) {}
static struct kobj_type __DRVHORN_ktype = {
    .release = __DRVHORN_kobject_release,
};

void __DRVHORN_setup_device(struct device *dev) {
  if (!dev)
    return;
  kobject_init(&dev->kobj, &__DRVHORN_ktype);
  dev->parent = NULL;
}

extern struct device_node *of_root;
void __DRVHORN_setup_of_root() {
  of_root = malloc(sizeof(struct device_node));
  of_root->child = NULL;
  kobject_init(&of_root->kobj, &__DRVHORN_ktype);
}

static void __DRVHORN_record_device_node(struct device_node *dn) {
  if (!dn)
    return;
  struct device_node *child = of_root->child;
  of_root->child = dn;
  dn->sibling = child;
}

struct device_node *__DRVHORN_get_device_node(struct device_node *from) {
  struct device_node *dn = NULL;
  if (nd_bool()) {
    dn = malloc(sizeof(struct device_node));
    kobject_init(&dn->kobj, &__DRVHORN_ktype);
    __DRVHORN_record_device_node(dn);
  }
  of_node_get(dn);
  of_node_put(from);
  return dn;
}

void __DRVHORN_check_device_node_refcounts() {
  struct device_node *dn = of_root->child;
  while (dn) {
    sassert(dn->kobj.kref.refcount.refs.counter == 1);
    dn = dn->sibling;
  }
}

static struct device *__DRVHORN_devices[0x100];
static size_t __DRVHORN_device_count = 0;
struct device *__DRVHORN_record_device(struct device *dev) {
  if (__DRVHORN_device_count < 0x100)
    __DRVHORN_devices[__DRVHORN_device_count++] = dev;
  return dev;
}

void __DRVHORN_check_device_refcounts() {
  for (size_t i = 0; i < __DRVHORN_device_count; i++) {
    int counter = __DRVHORN_util_get_device_counter(__DRVHORN_devices[i]);
    sassert(counter == 1);
  }
}
