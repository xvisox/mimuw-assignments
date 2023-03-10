#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void reverse(char const* str);

static const char * const test_data[] = {
  "Ala ma kota.",
  "!"
  ""
};

static const char * const reversed_data[] = {
  ".atok am alA",
  "!"
  ""
};

static size_t idx;

void reversed(char const* str) {
  register uint64_t rsp asm("rsp");
  volatile uint64_t x = rsp;
  assert((x & 0x7) == 0);
  assert(strcmp(str, reversed_data[idx]) == 0);
}

#define SIZE(x) (sizeof (x) / sizeof (x)[0])

int main() {
  for (idx = 0; idx < SIZE(test_data); ++idx) {
    char *buffer = strdup(test_data[idx]);
    reverse(buffer);
    assert(strcmp(buffer, test_data[idx]) == 0);
    free(buffer);
  }
}
