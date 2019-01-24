#ifndef PROJECT_ENCLVAE_UTILS_H
#define PROJECT_ENCLAVE_UTILS_H

#include "Enclave_t.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

int printf_std(const char *fmt, ...);

#ifdef __cplusplus
};
#endif

namespace utils
{
using std::string;
using std::vector;

}  // namespace utils
#endif  // PROJECT_UTILS_H
