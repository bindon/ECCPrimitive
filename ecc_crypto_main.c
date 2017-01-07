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
	unsigned char message[3000] = { 0, };
	int messageLength;
	GFP_POINT p;
	mpz_t r, s;
	mpz_t coefficientA, prime, order;
	gmp_randstate_t state;

	// ECDSA용 키
	mpz_t privateKey;
	GFP_POINT publicKey;

	// initialize
	GFP_init_point(&p);
	GFP_init_point(&publicKey);
	mpz_init(r);
	mpz_init(s);
	mpz_init(coefficientA);
	mpz_init(prime);
	mpz_init(order);
	mpz_init(privateKey);
	gmp_randinit_default(state);

	/*
	S = BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5
	r = 5B056C7E11DD68F40469EE7F3C7A7D74F7D121116506D031218291FB
	b = B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
	n = FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
	x = B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21
	y = BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34
	*/
	sprintf_s(message, 3000, "ecdsa 서명 테스트입니다.");
	messageLength = strlen(message);

	mpz_set_str(p.x, "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", 16);
	mpz_set_str(p.y, "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34", 16);
	p.isInfinity = FALSE;

	mpz_set_str(prime, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16);
	mpz_set_str(order, "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", 16);
	mpz_set_str(coefficientA, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", 16);

	/*
	mpz_set_str(k, "8364f5bea8fcbd885b98489a17a491400bfbd0a29382e32799f2242f", 16); // constants
	mpz_urandomm(k, state, prime); // random value
	*/

	printf("0. value generation\n");
	gmp_printf("\tP x : %Zx\n", p.x);
	gmp_printf("\tP y : %Zx\n", p.y);
	printf("\n");

	printf("1. generate key pair\n");
	/*
	S = BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5
	r = 5B056C7E11DD68F40469EE7F3C7A7D74F7D121116506D031218291FB
	b = B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
	n = FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
	x = B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21
	y = BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34
	*/
	if (ECDSA_key_pair_gen(privateKey, &publicKey, &p, order, coefficientA, prime)) {
		printf("키 생성 도중 오류가 발생하였습니다.\n");
		goto end;
	}
	gmp_printf("\tprivateKey  : %Zx\n", privateKey);
	gmp_printf("\tpublicKey.x : %Zx\n", publicKey.x);
	gmp_printf("\tpublicKey.y : %Zx\n", publicKey.y);
	printf("\n");

	printf("2. generate ECDSA Signature\n");
	if (ECDSA_sign_gen(r, s, message, messageLength, privateKey, &p, order, coefficientA, prime, HASH_ALGO_SHA224)) {
		printf("서명 생성 도중 오류가 발생하였습니다.\n");
		goto end;
	}
	gmp_printf("\tr : %Zx\n", r);
	gmp_printf("\ts : %Zx\n", s);
	printf("\n");

	printf("3. verify ECDSA Signature\n");
	if (ret = ECDSA_sign_ver(r, s, message, messageLength, &publicKey, &p, order, coefficientA, prime, HASH_ALGO_SHA224)) {
		printf("서명 검증 도중 오류가 발생하였습니다.\n");
		goto end;
	}
	printf("	VERIFY : %s\n", ret ? "FALSE" : "TRUE");

	ret = ECC_CRYPTO_SUCCESS;
end:
	// finalize
	mpz_clear(r);
	mpz_clear(s);
	mpz_clear(coefficientA);
	mpz_clear(prime);
	mpz_clear(order);
	mpz_clear(privateKey);
	GFP_clear_point(&p);
	GFP_clear_point(&publicKey);
	gmp_randclear(state);

	return ret;
}