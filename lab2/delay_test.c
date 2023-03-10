#include <assert.h>
#include <x86intrin.h>
#include <stdint.h>
#include <stdio.h>

uint64_t delay(uint64_t n);

int main()
{
  uint64_t n = 1000000000;
  delay(2); // Załaduj kod funkcji do pamięci podręcznej.
  uint64_t t0 = __rdtsc();
  delay(n);
  uint64_t t1 = __rdtsc();
  printf("%f\n", (double)(t1 - t0) / (double)n);
  return 0;
}
