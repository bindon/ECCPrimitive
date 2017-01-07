#ifndef ECC_CRYPTO_MAIN_H
#define ECC_CRYPTO_MAIN_H
#include <stdio.h>
#include <time.h>
#include "gmp.h"

typedef struct rsa_key_size {
	unsigned long keySize;
	int trustValue;
} rsa_key_size;

rsa_key_size KEY_SIZE_ARRAY[] = {
	{ 1024, 40 },
	{ 2048, 56 },
	{ 3072, 64 },
	{ 4096, 64 }
};

clock_t elapsed;
float sec;

#define IN
#define OUT
#define START_WATCH { elapsed = -clock(); }
#define STOP_WATCH { elapsed += clock(); sec = (float)elapsed/CLOCKS_PER_SEC; }
#define PRINT_TIME(qstr) { printf("[%s: %.5f s]\n", qstr, sec); }
#define ECC_CRYPTO_SUCCESS 0
#define ECC_CRYPTO_FAILED  1
#endif