#include "Enclave_t.h"

extern bool test_simple_cltv_redeem();
int enclaveTest()
{
  test_simple_cltv_redeem();

  return 0;
}