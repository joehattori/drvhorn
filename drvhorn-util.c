#include <asm/pgtable_types.h>
#include <linux/mm_types.h>
#include <linux/types.h>
#include <linux/nodemask.h>

extern _Bool nd();

void __DRVHORN_memset(void *s, char c, unsigned long long n, _Bool is_volatile) {
  int i;
  for (i = 0; i < n; i++)
    ((char*)s)[i] = c;
}

void __DRVHORN_memcpy(char *dst, char *src, unsigned long long n, _Bool is_volatile) {
  int i;
  for (i = 0; i < n; i++)
    dst[i] = src[i];
}

char __DRVHORN_memory_region[0x1000000];

// typedef void __attribute__((address_space(1))) *allocaddr;
void *__DRVHORN_malloc(unsigned long size) {
  static unsigned long long base = 0;
  if (nd()) {
    char *ret = __DRVHORN_memory_region + base;
    __DRVHORN_memset((void *)ret, 0, size, 0);
    base += size;
    return (void *)ret;
  } else {
    return 0;
  }
}

void *__attribute__((always_inline)) __DRVHORN___kmalloc(unsigned long size, unsigned flags) {
  return __DRVHORN_malloc(size);
}

void *__attribute__((always_inline)) __DRVHORN___kmalloc_node(unsigned long size, unsigned flags, int node) {
  return __DRVHORN_malloc(size);
}

void *__attribute__((always_inline)) __DRVHORN___kmalloc_node_track_caller(unsigned long size, unsigned flags, int node, unsigned long caller) {
  return __DRVHORN_malloc(size);
}

void *__attribute__((always_inline)) __DRVHORN_kmalloc_large(unsigned long size, unsigned flags) {
  return __DRVHORN_malloc(size);
}

void *__attribute__((always_inline)) __DRVHORN_kmalloc_large_node(unsigned long size, unsigned flags, int node) {
  return __DRVHORN_malloc(size);
}

void *__attribute__((always_inline)) __DRVHORN___vmalloc_node_range(unsigned long size, unsigned long align, unsigned long start, unsigned long end, unsigned int gfp_mask,
  pgprot_t prot, unsigned long vm_flags, int node,
  const void *caller) {
  return __DRVHORN_malloc(size);
}

void *__attribute__((always_inline)) __DRVHORN_pcpu_alloc(unsigned long size, unsigned long align, _Bool reserved, unsigned flags) {
  return __DRVHORN_malloc(size);
}

void *__DRVHORN___ioremap_caller(unsigned long long addr, unsigned long size, int prot, void *caller, _Bool d) {
  return __DRVHORN_malloc(size);
}

void *__DRVHORN___early_ioremap(resource_size_t phys_addr, unsigned long size,
                                pgprot_t prot) {
  return __DRVHORN_malloc(size);
}

struct page __DRVHORN_pages[0x100000];
struct page *__DRVHORN___alloc_pages() {
  static unsigned long long base = 0;
  if (nd()) {
    struct page *ret = __DRVHORN_pages + base;
    base++;
    return ret;
  } else {
    return 0;
  }
}

u64 __DRVHORN_util_read_u64(u8 *addr) { return *(u64 *)addr; }

u32 __DRVHORN_util_read_u32(u8 *addr) { return *(u32 *)addr; }

u16 __DRVHORN_util_read_u16(u8 *addr) { return *(u16 *)addr; }

u8 __DRVHORN_util_read_u8(u8 *addr) { return *addr; }
