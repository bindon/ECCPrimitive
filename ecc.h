/**
* Title  : Cryptographic Primitive Development
* Author : Choi Won Bin, Korea Univ.
* Date   : 2016-10-25, 2016-11-01, 2016-11-29
* Description
*	mpz_add_mod : 더하고 모듈러 적용
*	mpz_sub_mod : 빼고   모듈러 적용
*	mpz_mul_mod : 곱하고 모듈러 적용
*	GFP_fast_reduction_p256 : p256에서의 fast reduction
*	GFP_init_point(GFP_POINT *p);
*	GFP_clear_point(GFP_POINT *p);
*	GFP_affine_addition(OUT GFP_POINT *r, IN const GFP_POINT *p, IN const GFP_POINT *q, IN const mpz_t coefficientA, IN const mpz_t prime);
*	GFP_affine_doubling(OUT GFP_POINT *r, IN const GFP_POINT *p, IN const mpz_t coefficientA, IN const mpz_t prime);
*/
#ifndef ECC_H
#define ECC_H
#include "gmp.h"
#include "sha2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#define IN
#define OUT
#define TRUE 1
#define FALSE 0
#define ECC_CRYPTO_SUCCESS 0
#define ECC_CRYPTO_FAILED  1
#define HASH_ALGO_SHA224   1
#define HASH_ALGO_SHA256   2
#define HASH_ALGO_SHA384   3
#define HASH_ALGO_SHA512   4

typedef struct _GFP_POINT
{
	mpz_t x;
	mpz_t y;
	int isInfinity;
} GFP_POINT;

typedef struct _NAF_RECORDING
{
	char naf_scalar[1024];
	int naf_len;
} NAF_RECORDING;

typedef struct _ECC_HASH_ALGORITHM
{
	void (*digest)(const unsigned char *m, unsigned int len, unsigned char *hash);
	int digestLength;
	int blockLength;
} ECC_HASH_ALGORITHM;

static const ECC_HASH_ALGORITHM eccHashAlgorithm[10] = {
	{ 0,0,0 },
	{ sha224, SHA224_DIGEST_SIZE, SHA224_BLOCK_SIZE },
	{ sha256, SHA256_DIGEST_SIZE, SHA256_BLOCK_SIZE },
	{ sha384, SHA384_DIGEST_SIZE, SHA384_BLOCK_SIZE },
	{ sha512, SHA512_DIGEST_SIZE, SHA512_BLOCK_SIZE },
};
// return r = a+b (mod n)
void mpz_add_mod(OUT mpz_t r, IN const mpz_t a, IN const mpz_t b, IN const mpz_t n);

// return r = a-b (mod n)
void mpz_sub_mod(OUT mpz_t r, IN const mpz_t a, IN const mpz_t b, IN const mpz_t n);

// return r = a*b (mod n)
void mpz_mul_mod(OUT mpz_t r, IN const mpz_t a, IN const mpz_t b, IN const mpz_t n);

// fast reduction modulo p256 = 2^256 - 2^224 + 2^192 + 2^96 - 1
// return r = a (mod n)
int GFP_fast_reduction_p256(OUT mpz_t r, IN const mpz_t a, IN const mpz_t n);

// point initialize
void GFP_init_point(GFP_POINT *p);

// point clear
void GFP_clear_point(GFP_POINT *p);

// point set
void GFP_set_point(OUT GFP_POINT *dst, const IN GFP_POINT *src);

// point addition (r=p+q)
int GFP_affine_addition(OUT GFP_POINT *r, IN const GFP_POINT *p, IN const GFP_POINT *q, IN const mpz_t coefficientA, IN const mpz_t prime);

// point doubling (r=2p)
int GFP_affine_doubling(OUT GFP_POINT *r, IN const GFP_POINT *p, IN const mpz_t coefficientA, IN const mpz_t prime);

// R=kP LtoR binary multiplication
int GFP_mul_binary_ltor(OUT GFP_POINT *r, IN const mpz_t k, IN const GFP_POINT *p, IN const mpz_t coefficientA, IN const mpz_t prime);

// R=kP LtoR NAF
int GFP_naf_recording(OUT NAF_RECORDING *rk, IN const mpz_t k);
int GFP_naf_ltor(OUT GFP_POINT *r, IN const NAF_RECORDING *k, IN const GFP_POINT *p, IN const mpz_t coefficientA, IN const mpz_t prime);

// ECDSA keypair gen
int ECDSA_key_pair_gen(OUT mpz_t privateKey, OUT GFP_POINT *publicKey, IN GFP_POINT *p, IN mpz_t order, IN const mpz_t coefficientA, IN const mpz_t prime);

// generate ECDSA sign
int ECDSA_sign_gen(OUT mpz_t r, OUT mpz_t s, IN unsigned char *message, IN int messageLength, IN mpz_t privateKey, IN GFP_POINT *p, IN mpz_t order, IN const mpz_t coefficientA, IN const mpz_t prime, IN int hashAlgorithm);

// verify ECDSA sign
int ECDSA_sign_ver(IN mpz_t r, IN mpz_t s, IN unsigned char *message, IN int messageLength, IN GFP_POINT *publicKey, IN GFP_POINT *p, IN mpz_t order, IN const mpz_t coefficientA, IN const mpz_t prime, IN int hashAlgorithm);

// convert unsigned char to big number
int ostr2mpz(mpz_t a, const unsigned char *ostr, const int ostrlen);
#endif
