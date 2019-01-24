#include <sgx_urts.h>
#include <iostream>
#include "Enclave_u.h"
#include "enclave_utils.h"

using std::cerr;
using std::endl;

sgx_enclave_id_t eid;

int main(int argc, const char *argv[])
{
  // try to create an enclave
  if (0 != initialize_enclave(&eid)) {
    cerr << "failed to init enclave" << endl;
    exit(-1);
  }

  sgx_status_t st;
  int ret = 0;

  // call the function at Enclave/enclave_test.cpp:55
  st = enclaveTest(eid, &ret);
  if (st != SGX_SUCCESS) {
    cerr << "ecall failed with return value " << endl;
  }

  // destroy the enclave last
  sgx_destroy_enclave(eid);
}
