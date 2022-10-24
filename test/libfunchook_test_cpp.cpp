#include "libfunchook_test.h"

TestCpp::TestCpp() {
  m_ = 0;
}

long TestCpp::call(long a, long b) {
  return m_ + a + b;
}
