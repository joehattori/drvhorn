extern void __VERIFIER_assume(int);
extern void *nd_malloc(void);

inline void *__VERIFIER_memset(void *s, int c, unsigned long n) {
  int i;
  for (i = 0; i < n; i++)
    ((char*)s)[i] = 0;
  return s;
}

void *__VERIFIER_malloc(unsigned long size) {
  void *res = nd_malloc();
  if (res) {
    __VERIFIER_memset(res, 0, size);
  }
  return res;
}
