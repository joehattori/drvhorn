extern void __VERIFIER_assume(int);

void *memset(void *s, int c, unsigned long n) {
  int i;
  char *ss = s;

  for (i = 0; i < n; i++)
    __VERIFIER_assume(ss[i] == 0);
  return s;
}
