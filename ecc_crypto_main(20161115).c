/**
 * Title  : Cryptographic Primitive Development
 * Author : Choi Won Bin, Korea Univ.
 * Date   : 2016-11-08
 */

#include "ecc_crypto_main.h"
#include "ecc.h"

int main(int argc, char *argv[], char *env[])
{
	int ret = ECC_CRYPTO_FAILED;
	int idx = 0;

	// definition
	GFP_POINT p, q, r;
	mpz_t coefficientA, prime;

	// initialize
	GFP_init_point(&p);
	GFP_init_point(&q);
	GFP_init_point(&r);
	mpz_init(coefficientA);
	mpz_init(prime);

	mpz_set_str(p.x, "4aca3a8c7b99b7f69c404cad9c2d4f70a5e14b9235ed2a6fdbebab71", 16);
	mpz_set_str(p.y, "da8d9d45495391c9b69bc714294318a04afe22b294c3b682b985129b", 16);
	p.isInfinity = 0;

	mpz_set_str(q.x, "3e54b1067d79dab2bd159a61f03e7bcb62851c5d3418a8bc5cad16aa", 16);
	mpz_set_str(q.y, "5986453b559d4ce6b24a4f10a87efe19eaf49a6db877bda6b791adb3", 16);
	q.isInfinity = 0;

	mpz_set_str(prime, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16);
	mpz_set_str(coefficientA, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", 16);

	if (GFP_affine_doubling(&r, &p, coefficientA, prime)) {
		printf("doubling 도중 오류가 발생하였습니다.\n");
		goto end;
	}
	printf("0. value generation\n");
	gmp_printf("P x : %Zx\n", p.x);
	gmp_printf("P y : %Zx\n", p.y);
	gmp_printf("Q x : %Zx\n", q.x);
	gmp_printf("Q y : %Zx\n", q.y);
	printf("\n\n");

	printf("1. 2P\n");
	gmp_printf("result x : %Zx\n", r.x);
	gmp_printf("result y : %Zx\n", r.y);
	printf("\n\n");

	if (GFP_affine_addition(&r, &p, &q, coefficientA, prime)) {
		printf("addition 도중 오류가 발생하였습니다.\n");
		goto end;
	}
	printf("2. P+Q\n");
	gmp_printf("result x : %Zx\n", r.x);
	gmp_printf("result y : %Zx\n", r.y);

	ret = ECC_CRYPTO_SUCCESS;

end:
	// finalize
	mpz_clear(prime);
	mpz_clear(coefficientA);
	GFP_clear_point(&r);
	GFP_clear_point(&q);
	GFP_clear_point(&p);

	return ret;
}