/**
 * Title  : Cryptographic Primitive Development
 * Author : Choi Won Bin, Korea Univ.
 * Date   : 2016-11-22
 *		1) kG (binary scalar multiplication, binary NAF scalar multiplication)
 *		2) SHA2
 *		3) Domain Parameter
 */

#include "ecc_crypto_main.h"
#include "ecc.h"

int main(int argc, char *argv[], char *env[])
{
	int ret = ECC_CRYPTO_FAILED;
	int idx = 0;

	// definition
	GFP_POINT p, r;
	GFP_POINT resultBinMul, resultNAFMul;
	NAF_RECORDING naf;
	mpz_t coefficientA, prime, k;
	gmp_randstate_t state;

	// initialize
	GFP_init_point(&p);
	GFP_init_point(&r);
	GFP_init_point(&resultBinMul);
	GFP_init_point(&resultNAFMul);
	mpz_init(coefficientA);
	mpz_init(prime);
	mpz_init(k);
	gmp_randinit_default(state);

	mpz_set_str(p.x, "4aca3a8c7b99b7f69c404cad9c2d4f70a5e14b9235ed2a6fdbebab71", 16);
	mpz_set_str(p.y, "da8d9d45495391c9b69bc714294318a04afe22b294c3b682b985129b", 16);
	p.isInfinity = FALSE;

	mpz_set_str(prime, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16);
	mpz_set_str(coefficientA, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", 16);

	naf.naf_len = 0;

	mpz_set_str(k, "8364f5bea8fcbd885b98489a17a491400bfbd0a29382e32799f2242f", 16); // constants
	mpz_urandomm(k, state, prime); // random value

	printf("0. value generation\n");
	gmp_printf("\tP x : %Zx\n", p.x);
	gmp_printf("\tP y : %Zx\n", p.y);
	gmp_printf("\tk(scalar) : %Zx\n", k);
	printf("\n");

	START_WATCH;
	for (idx = 0; idx < 100; idx++) {
		if (GFP_mul_binary_ltor(&r, k, &p, coefficientA, prime)) {
			printf("mul binary left to right 도중 오류가 발생하였습니다.\n");
			goto end;
		}
	}
	STOP_WATCH;
	GFP_set_point(&resultBinMul, &r);

	printf("1. mul binary ltor\n");
	gmp_printf("\tresult x : %Zx\n", resultBinMul.x);
	gmp_printf("\tresult y : %Zx\n", resultBinMul.y);
	PRINT_TIME("binary multiplication : ");
	printf("\n");

	START_WATCH;
	for (idx = 0; idx < 100; idx++) {
		if (GFP_naf_recording(&naf, k)) {
			printf("naf recording 도중 오류가 발생하였습니다.\n");
			goto end;
		}

		if (GFP_naf_ltor(&r, &naf, &p, coefficientA, prime)) {
			printf("addition 도중 오류가 발생하였습니다.\n");
			goto end;
		}
	}
	STOP_WATCH;
	printf("2. naf recording\n");
	printf("\tnaf_len : %d\n", naf.naf_len);
	printf("\n");

	GFP_set_point(&resultNAFMul, &r);

	printf("3. naf ltor\n");
	gmp_printf("\tresult x : %Zx\n", r.x);
	gmp_printf("\tresult y : %Zx\n", r.y);
	PRINT_TIME("NAF multiplication : ");
	printf("\n");

	printf("4. verify binary multiplication and naf multiplication\n");
	printf("\tverify x axis : %s\n", mpz_cmp(resultBinMul.x, resultNAFMul.x) == 0 ? "TRUE" : "FALSE");
	printf("\tverify y axis : %s\n", mpz_cmp(resultBinMul.y, resultNAFMul.y) == 0 ? "TRUE" : "FALSE");

	ret = ECC_CRYPTO_SUCCESS;
end:
	// finalize
	mpz_clear(prime);
	mpz_clear(coefficientA);
	mpz_clear(k);
	GFP_clear_point(&r);
	GFP_clear_point(&p);
	GFP_clear_point(&resultBinMul);
	GFP_clear_point(&resultNAFMul);
	gmp_randclear(state);

	return ret;
}