#include "queue.h"
#include <assert.h>
#include <stdint.h>

int main() {
  assert(queue_is_empty() == true);
  assert(queue_is_full() == false);

  queue_put(7);
  queue_put(-3);
  queue_put(0);

  assert(queue_is_empty() == false);
  assert(queue_is_full() == false);

  assert(queue_get() == 7);
  assert(queue_get() == -3);
  assert(queue_get() == 0);

  assert(queue_is_empty() == true);
  assert(queue_is_full() == false);

  for (int16_t i = 1; i <= 18; ++i)
    queue_put(i);

  assert(queue_is_empty() == false);
  assert(queue_is_full() == true);

  for (int16_t i = 1; i <= 16; ++i)
    assert(queue_get() == i);

  assert(queue_is_empty() == true);
  assert(queue_is_full() == false);

  queue_get();
  queue_get();

  assert(queue_is_empty() == true);
  assert(queue_is_full() == false);

  queue_put(17);
  assert(queue_get() == 17);
}
