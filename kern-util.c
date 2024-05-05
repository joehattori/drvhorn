extern void __VERIFIER_assume(int);
extern void *nd_malloc(void);

void __VERIFIER_memset(void *s, char c, unsigned long long n, _Bool is_volatile) {
  int i;
  for (i = 0; i < n; i++)
    ((char*)s)[i] = c;
}

void __VERIFIER_memcpy(char *dst, char *src, unsigned long long n, _Bool is_volatile) {
  int i;
  for (i = 0; i < n; i++)
    dst[i] = src[i];
}

void *__VERIFIER_malloc(unsigned long size) {
  void *res = nd_malloc();
  if (res) {
    __VERIFIER_memset(res, 0, size, 0);
  }
  return res;
}
