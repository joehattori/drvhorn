#include <asm/pgtable_types.h>
#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/mm_types.h>
#include <linux/nodemask.h>
#include <linux/types.h>
#include <linux/of.h>
#include <linux/device/class.h>
#include <linux/slab.h>
#include <base/base.h>

extern _Bool nd_bool();
extern char nd_char();
extern int nd_int();
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

static int __DRVHORN_util_get_kobject_count(const struct kobject *kobj) {
  return kobj->kref.refcount.refs.counter;
}

static void __DRVHORN_kobject_release(struct kobject *kobj) {}
struct kobj_type __DRVHORN_ktype = {
    .release = __DRVHORN_kobject_release,
};

static struct kobject *device_node_kobject;
static void __DRVHORN_record_device_node_kobject(struct kobject *k) {
  if (nd_bool()) {
    device_node_kobject = k;
  }
}

static struct kobject *dev_kobject;
static void __DRVHORN_record_device_kobject(struct kobject *k) {
  if (nd_bool()) {
    dev_kobject = k;
  }
}

static struct device_node *__DRVHORN_create_device_node(void) {
#define LIMIT 0x10000
  static unsigned counter = 0;
  static struct device_node storage[LIMIT];

  if (nd_bool() || counter >= LIMIT)
    return NULL;
  struct device_node *dn = &storage[counter++];
  kobject_init(&dn->kobj, &__DRVHORN_ktype);
  __DRVHORN_record_device_node_kobject(&dn->kobj);
  return dn;
}

struct device_node *__DRVHORN_get_device_node(struct device_node *from) {
  struct device_node *dn = __DRVHORN_create_device_node();
  of_node_get(dn);
  of_node_put(from);
  return dn;
}

void __DRVHORN_setup_device(struct device *dev) {
  kobject_init(&dev->kobj, &__DRVHORN_ktype);
  __DRVHORN_record_device_kobject(&dev->kobj);
  // dev->of_node = __DRVHORN_create_device_node();
}

void __DRVHORN_assert(void) {
  if (device_node_kobject) {
    int counter = __DRVHORN_util_get_kobject_count(device_node_kobject);
    /*sassert(counter == 1 || counter == 2);*/
    /*sassert(counter == 1 || counter == 0);*/
    sassert(counter == 1);
  }
  if (dev_kobject) {
    int counter = __DRVHORN_util_get_kobject_count(dev_kobject);
    /*sassert(counter == 1 || counter == 2);*/
    /*sassert(counter == 1 || counter == 0);*/
    sassert(counter == 1);
  }
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

int __DRVHORN_device_add(struct device *dev) {
  int error = -EINVAL;
  dev = get_device(dev);
  if (!dev)
    goto done;
  if (!dev->p) {
    error = __DRVHORN_device_private_init(dev);
    if (error)
      goto done;
  }
  return 0;
done:
  put_device(dev);
  return error;
}

int __DRVHORN_of_phandle_iterator_next(struct of_phandle_iterator *it) {
  of_node_put(it->node);
  it->node = NULL;
  if (nd_bool()) {
    return -1;
  }
  it->node = of_find_node_by_phandle(it->phandle);
  return 0;
}
