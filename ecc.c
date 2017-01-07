#include "ecc.h"


int ostr2mpz(mpz_t a, const unsigned char *ostr, const int ostrlen) {
	int i, bytelen;
	if (ostrlen == 0) { a->_mp_size = 0; return 0; }
	if ((a == 0) || (ostr == 0)) return -1;  bytelen = ostrlen - 1; a->_mp_size = (ostrlen + 3) >> 2;
	if (a->_mp_alloc < a->_mp_size) mpz_realloc2(a, (a->_mp_size << 5)); memset((unsigned int *)a->_mp_d, 0, (a->_mp_size << 2)); for (i = bytelen; i >= 0; i--) { a->_mp_d[(bytelen - i) >> 2] |= ((ostr[i]) << (((bytelen - i) & 0x3) << 3)); }
	return 0;
}

void mpz_add_mod(OUT mpz_t r, IN const mpz_t a, IN const mpz_t b, IN const mpz_t n)
{
	mpz_add(r, a, b);
	if (mpz_cmp(r, n) >= 0) {
		mpz_sub(r, r, n);
	} // mpz_mod(r, r, n);
}

void mpz_sub_mod(OUT mpz_t r, IN const mpz_t a, IN const mpz_t b, IN const mpz_t n)
{
	mpz_sub(r, a, b);
	if (mpz_sgn(r) < 0) {
		mpz_add(r, r, n);
	} // mpz_mod(r, r, n);
}

void mpz_mul_mod(OUT mpz_t r, IN const mpz_t a, IN const mpz_t b, IN const mpz_t n)
{
	mpz_mul(r, a, b);
	mpz_mod(r, r, n);
}

int GFP_fast_reduction_p256(OUT mpz_t r, IN const mpz_t a, IN const mpz_t n)
{
	if (a->_mp_size < a->_mp_alloc) {
		memset(a->_mp_d + a->_mp_size, 0, sizeof(unsigned long) * (a->_mp_alloc-a->_mp_size));
	}

	// definition constants
	const unsigned long sArray[9][8] = {
		{ a->_mp_d[7],  a->_mp_d[6],  a->_mp_d[5],  a->_mp_d[4],  a->_mp_d[3],  a->_mp_d[2],  a->_mp_d[1],  a->_mp_d[0]  }, // s1
		{ a->_mp_d[15], a->_mp_d[14], a->_mp_d[13], a->_mp_d[12], a->_mp_d[11], 0,            0,            0            }, // s2
		{ 0,            a->_mp_d[15], a->_mp_d[14], a->_mp_d[13], a->_mp_d[12], 0,            0,            0            }, // s3
		{ a->_mp_d[15], a->_mp_d[14], 0,            0,            0,            a->_mp_d[10], a->_mp_d[9],  a->_mp_d[8]  }, // s4
		{ a->_mp_d[8],  a->_mp_d[13], a->_mp_d[15], a->_mp_d[14], a->_mp_d[13], a->_mp_d[11], a->_mp_d[10], a->_mp_d[9]  }, // s5
		{ a->_mp_d[10], a->_mp_d[8],  0,            0,            0,            a->_mp_d[13], a->_mp_d[12], a->_mp_d[11] }, // s6
		{ a->_mp_d[11], a->_mp_d[9],  0,            0,            a->_mp_d[15], a->_mp_d[14], a->_mp_d[13], a->_mp_d[12] }, // s7
		{ a->_mp_d[12], 0,            a->_mp_d[10], a->_mp_d[9],  a->_mp_d[8],  a->_mp_d[15], a->_mp_d[14], a->_mp_d[13] }, // s8
		{ a->_mp_d[13], 0,            a->_mp_d[11], a->_mp_d[10], a->_mp_d[9],  0,            a->_mp_d[15], a->_mp_d[14] }  // s9
	};
	const int sArrayRow = 9;
	const int sArrayCol = 8;

	// definition
	int ret = ECC_CRYPTO_FAILED;
	int idx, idxS, idxC;
	mpz_t s[9];

	// initialize
	mpz_init2(s[0], 512);
	mpz_init2(s[1], 288);
	mpz_init2(s[2], 288);
	for (idx = 3; idx < sArrayRow; idx++) {
		mpz_init2(s[idx], 256);
	}

	if ((mpz_size(a) < 0) || (mpz_size(a) > 16)) {
		printf("연산할 수 있는 범위를 벗어났습니다. [%d]\n", mpz_size(a));
		goto end;
	}

	// 1. Define 256-bit integers
	for (idxS = 0; idxS < sArrayRow; idxS++) {
		memset(s[idxS]->_mp_d, 0, sizeof(unsigned long) * s[idxS]->_mp_alloc);
		for (idxC = 0; idxC < sArrayCol; idxC++) {
			s[idxS]->_mp_d[sArrayCol-idxC-1] = sArray[idxS][idxC];
		}
		s[idxS]->_mp_size = 8;
	}
	
	mpz_add(s[1], s[1], s[1]); // 2s2를 구함
	mpz_add(s[2], s[2], s[2]); // 2s3을 구함
	mpz_add(s[0], s[0], s[1]); // s1 + 2s2
	mpz_add(s[0], s[0], s[2]); // + 2s3
	mpz_add(s[0], s[0], s[3]); // + s4
	mpz_add(s[0], s[0], s[4]); // + s5
	mpz_sub(s[0], s[0], s[5]); // - s6
	s[0]->_mp_size = 16; // sub연산 이후에 size값이 마이너스로 변경될 때가 있음
	mpz_sub(s[0], s[0], s[6]); // - s7
	s[0]->_mp_size = 16; // sub연산 이후에 size값이 마이너스로 변경될 때가 있음
	mpz_sub(s[0], s[0], s[7]); // - s8
	s[0]->_mp_size = 16; // sub연산 이후에 size값이 마이너스로 변경될 때가 있음
	mpz_sub(s[0], s[0], s[8]); // - s9

	// mod p256
	while (mpz_cmp(s[0], n) >= 0) {
		mpz_sub(s[0], s[0], n);
	}

	while (mpz_sgn(s[0]) < 0) {
		mpz_add(s[0], s[0], n);
	}

	mpz_set(r, s[0]);
	
	ret = ECC_CRYPTO_SUCCESS;
end:
	// finalize
	for (idx = 0; idx < sArrayRow; idx++) {
		mpz_clear(s[idx]);
	}

	return ret;
}

// initialize point
void GFP_init_point(GFP_POINT *p)
{
	mpz_init(p->x);
	mpz_init(p->y);
	p->isInfinity = TRUE;
}

// clear point
void GFP_clear_point(GFP_POINT *p)
{
	mpz_clear(p->x);
	mpz_clear(p->y);
}

// set point
void GFP_set_point(OUT GFP_POINT *dst, IN const GFP_POINT *src)
{
	mpz_set(dst->x, src->x);
	mpz_set(dst->y, src->y);
	dst->isInfinity = src->isInfinity;
}

// 1. if p == isInfinity then r = q
// 2. if q == isInfinity then r = p
// 3. if x1 == x2 then
//   1) y1==y2 then doubling
//   2) y1!=y2 then r->isInfinity = 1
int GFP_affine_addition(OUT GFP_POINT *r, IN const GFP_POINT *p, IN const GFP_POINT *q, IN const mpz_t coefficientA, IN const mpz_t prime)
{
	// definition
	int ret = ECC_CRYPTO_FAILED;
	mpz_t tempValue1, tempValue2, tempValue3;

	// initialize
	mpz_init(tempValue1);
	mpz_init(tempValue2);
	mpz_init(tempValue3);

	if (p->isInfinity) {
		GFP_set_point(r, q);
		ret = ECC_CRYPTO_SUCCESS;
		goto end;
	}

	if (q->isInfinity) {
		GFP_set_point(r, p);
		ret = ECC_CRYPTO_SUCCESS;
		goto end;
	}

	if (!mpz_cmp(p->x, q->x)) {
		if (mpz_cmp(p->y, q->y)) {
			printf("p와 q의 값이 같습니다.\n");
			r->isInfinity = TRUE;
		} else {
			GFP_affine_doubling(r, p, coefficientA, prime);
			ret = ECC_CRYPTO_SUCCESS;
		}
		goto end;
	}

	// 1. x3 구하기
	//   1) y2-y1
	mpz_sub_mod(tempValue1, q->y, p->y, prime);
	//   2) x2-x1
	mpz_sub_mod(tempValue2, q->x, p->x, prime);
	// invert 이후 곱하기
	mpz_invert(tempValue2, tempValue2, prime);
	mpz_mul_mod(tempValue3, tempValue1, tempValue2, prime);
	// ^2
	mpz_mul_mod(tempValue1, tempValue3, tempValue3, prime);
	// -x1
	mpz_sub_mod(tempValue1, tempValue1, p->x, prime);
	// -x2
	mpz_sub_mod(tempValue2, tempValue1, q->x, prime);


	// 2. y3 구하기
	//   1) (x1 - x3) 구하기
	mpz_sub(tempValue1, p->x, tempValue2);
	//   2) tempValue3 * tempValue1
	mpz_mul_mod(tempValue1, tempValue3, tempValue1, prime);
	//   3) -y1
	mpz_sub_mod(r->y, tempValue1, p->y, prime);

	// set x3
	mpz_set(r->x, tempValue2);

	// 3. r의 isInfinity 값 FALSE로 변경
	r->isInfinity = FALSE;

	ret = ECC_CRYPTO_SUCCESS;
end:
	// finalize
	mpz_clear(tempValue1);
	mpz_clear(tempValue2);
	mpz_clear(tempValue3);

	return ret;
}

// 1. if p->isInfinity then r->isInfinity == 1 
// 2. if y1 == 0 then error
int GFP_affine_doubling(OUT GFP_POINT *r, IN const GFP_POINT *p, IN const mpz_t coefficientA, IN const mpz_t prime)
{
	// definition
	int ret = ECC_CRYPTO_FAILED;
	mpz_t tempValue1, tempValue2, tempValue3;

	// initialize
	mpz_init(tempValue1);
	mpz_init(tempValue2);
	mpz_init(tempValue3);

	if (p->isInfinity) {
		r->isInfinity = TRUE;
		ret = ECC_CRYPTO_SUCCESS;
		goto end;
	}

	if (!mpz_cmp_ui(p->y, 0)) {
		goto end;
	}

	// 1. x3 구하기
	//   1) 3*x1^2 + a
	// x1 ^ 2
	mpz_mul_mod(tempValue1, p->x, p->x, prime);
	// *3
	mpz_mul_ui(tempValue1, tempValue1, 3);
	mpz_mod(tempValue1, tempValue1, prime);
	// +a
	mpz_add_mod(tempValue1, tempValue1, coefficientA, prime);
	//   2) 2y1
	mpz_add(tempValue2, p->y, p->y);
	mpz_mod(tempValue2, tempValue2, prime);
	// ^-1
	mpz_invert(tempValue2, tempValue2, prime);
	//   3) tempValue1 * tempValue2 추후에 쓸 에정이므로 tempValue3에 저장
	mpz_mul_mod(tempValue3, tempValue1, tempValue2, prime);
	//   4) ^2
	mpz_mul_mod(tempValue1, tempValue3, tempValue3, prime);

	//   5) 2x1
	mpz_mul_ui(tempValue2, p->x, 2);
	mpz_mod(tempValue2, tempValue2, prime);

	//   6) x3 = tempValue1 - tempValue2
	mpz_sub_mod(tempValue2, tempValue1, tempValue2, prime);

	// 2. y3 구하기
	//   1) (x1 - x3) 구하기
	mpz_sub(tempValue1, p->x, tempValue2);
	//   2) tempValue3 * tempValue1
	mpz_mul_mod(tempValue1, tempValue3, tempValue1, prime);
	//   3) -y1
	mpz_sub_mod(r->y, tempValue1, p->y, prime);
	
	// set x3
	mpz_set(r->x, tempValue2);

	// 3. r의 isInfinity 값 FALSE로 변경
	r->isInfinity = FALSE;

	ret = ECC_CRYPTO_SUCCESS;
end:
	// finalize
	mpz_clear(tempValue1);
	mpz_clear(tempValue2);
	mpz_clear(tempValue3);

	return ret;
}

int GFP_mul_binary_ltor(OUT GFP_POINT *r, IN const mpz_t k, IN const GFP_POINT *p, IN const mpz_t coefficientA, IN const mpz_t prime)
{
	// definition
	int ret = ECC_CRYPTO_FAILED;
	int arrayIdx, bitIdx;
	GFP_POINT result;

	// initialize
	GFP_init_point(&result);

	// validation check
	if (k->_mp_size < 0) { // minus
		printf("k가 음수입니다.\n");
		goto end;
	}

	// business logic
	for (arrayIdx = k->_mp_size - 1; arrayIdx >= 0; arrayIdx--) {
		for (bitIdx = 31; bitIdx >= 0; bitIdx--) {
			GFP_affine_doubling(&result, &result, coefficientA, prime); // 두배
			if ((k->_mp_d[arrayIdx] >> bitIdx) & 1) { // 1을 만나면
				GFP_affine_addition(&result, &result, p, coefficientA, prime);
			}
		}
	}

	GFP_set_point(r, &result);

	ret = ECC_CRYPTO_SUCCESS;
end:
	// finalize
	GFP_clear_point(&result);

	return ret;
}

int GFP_naf_recording(OUT NAF_RECORDING *rk, IN const mpz_t k)
{
	// definition
	int ret = ECC_CRYPTO_FAILED;
	int arrayIdx, bitIndex, currentValue, carry = 0;
	int currentIndex;
	NAF_RECORDING result;

	// validation check
	if (k->_mp_size < 0) {
		printf("k가 음수입니다.\n");
		goto end;
	}

	// business logic
	result.naf_len = 0;
	for (arrayIdx = 0; arrayIdx < k->_mp_size; arrayIdx++) { // 제일 작은 부분부터 탐색
		for (bitIndex = 0; bitIndex < 32; bitIndex++) { // LSB부터 탐색
			result.naf_len++;
			currentValue = (k->_mp_d[arrayIdx] >> bitIndex) & 3; // 2개의 비트 (11)
			currentIndex = arrayIdx * 32 + bitIndex;
			result.naf_scalar[currentIndex] = 0; // 0을 기본적으로 넣어주면 편함
			if (carry) {
				switch (currentValue) {
				case 0: // 00
				case 2: // 10
					result.naf_scalar[currentIndex] = 1;
					carry = 0;
					break;
				}
			}
			else {
				switch (currentValue) {
				case 1: // 01
					result.naf_scalar[currentIndex] = 1;
					break;
				case 3: // 11
					result.naf_scalar[currentIndex] = -1;
					carry = 1;
					break;
				}
			}
		}
	}

	// MSB가 1이면 한 바이트가 넘어가기 때문에 for문에서 체크가 불가능하므로 예외처리가 필요함
	// 매우 쉬운 예제로 k에 F를 가득 넣고 실행하면 100...000(-1)이 되어 FF...FF로 되어야함
	if (carry) {
		result.naf_scalar[result.naf_len++] = 1;
	}

	rk->naf_len = result.naf_len;
	memcpy(rk->naf_scalar, result.naf_scalar, 1024);

	ret = ECC_CRYPTO_SUCCESS;
end:
	// finalize

	return ret;
}

int GFP_naf_ltor(OUT GFP_POINT *r, IN const NAF_RECORDING *k, IN const GFP_POINT *p, IN const mpz_t coefficientA, IN const mpz_t prime)
{
	// definition
	int ret = ECC_CRYPTO_FAILED;
	int arrayIdx;
	GFP_POINT result;
	GFP_POINT minusP;

	// initialize
	GFP_init_point(&result);
	GFP_init_point(&minusP);
	
	// set minus p
	GFP_set_point(&minusP, p);
	minusP.y->_mp_size *= -1;

	// validation check
	if (k->naf_len < 0) {
		printf("k가 음수입니다.\n");
		goto end;
	}

	// business logic
	for (arrayIdx = k->naf_len-1; arrayIdx >= 0; arrayIdx--) {
		GFP_affine_doubling(&result, &result, coefficientA, prime); // 두배
		switch(k->naf_scalar[arrayIdx]) {
		case 1:
			GFP_affine_addition(&result, &result, p, coefficientA, prime);
			break;
		case -1:
			GFP_affine_addition(&result, &result, &minusP, coefficientA, prime);
			break;
		}
	}

	GFP_set_point(r, &result);

	ret = ECC_CRYPTO_SUCCESS;
end:
	// finalize
	GFP_clear_point(&result);
	GFP_clear_point(&minusP);

	return ret;
}

// ECDSA keypair gen
int ECDSA_key_pair_gen(OUT mpz_t privateKey, OUT GFP_POINT *publicKey, IN GFP_POINT *p, IN mpz_t order, IN const mpz_t coefficientA, IN const mpz_t prime)
{
	// definition
	int ret = ECC_CRYPTO_FAILED;
	gmp_randstate_t state;

	// initialize
	gmp_randinit_default(state);

	// business logic
	// 1. generate private key
	mpz_urandomm(privateKey, state, order);

	// 2. generate public key
	if (GFP_mul_binary_ltor(publicKey, privateKey, p, coefficientA, prime)) {
		printf("left to right 이진 곱셈 연산 도중 오류가 발생하였습니다.\n");
		goto end;
	}

	ret = ECC_CRYPTO_SUCCESS;
end:
	// finalize
	gmp_randclear(state);

	return ret;
}

// generate ECDSA sign
int ECDSA_sign_gen(OUT mpz_t r, OUT mpz_t s, IN unsigned char *message, IN int messageLength, IN mpz_t privateKey, IN GFP_POINT *p, IN mpz_t order, IN const mpz_t coefficientA, IN const mpz_t prime, IN int hashAlgorithm)
{
	// definition
	int ret = ECC_CRYPTO_FAILED;
	unsigned char *eArray;
	mpz_t k, kInverse, e, tempValue;
	gmp_randstate_t state;
	GFP_POINT kP;

	// initialize
	eArray = (unsigned char *)malloc(eccHashAlgorithm[hashAlgorithm].digestLength);
	mpz_init(e);
	mpz_init(k);
	mpz_init(kInverse);
	mpz_init(tempValue);
	gmp_randinit_default(state);
	GFP_init_point(&kP);

	// validation check
	if (hashAlgorithm < 1 || hashAlgorithm > 4) {
		printf("올바른 해쉬 알고리즘을 선택 해 주세요.\n");
		goto end;
	}

	// business logic
	while (1) {
		// 1. select k
		mpz_urandomm(k, state, order);

		// 2. compute kP
		GFP_mul_binary_ltor(&kP, k, p, coefficientA, prime);

		// 3. r = x mod n
		mpz_mod(r, kP.x, order);
		if (!mpz_cmp_ui(r, 0)) {
			continue; // goto step 1
		}

		// 4. compute e = H(m)
		eccHashAlgorithm[hashAlgorithm].digest(message, messageLength, eArray);
		ostr2mpz(e, eArray, messageLength);

		// 5. compute s = k^(-1) * (e + dr) mod n
		// compute dr
		mpz_mul_mod(tempValue, privateKey, r, order);
		// compute +e
		mpz_add_mod(tempValue, tempValue, e, order);
		// compute *kInverse
		mpz_invert(kInverse, k, order);
		mpz_mul_mod(s, tempValue, kInverse, order);
		if (!mpz_cmp_ui(s, 0)) {
			continue;
		}
		break;
	}

	ret = ECC_CRYPTO_SUCCESS;
end:
	// finalize
	free(eArray);
	mpz_clear(e);
	mpz_clear(k);
	mpz_clear(kInverse);
	mpz_clear(tempValue);
	gmp_randclear(state);
	GFP_clear_point(&kP);

	return ret;
}

// verify ECDSA sign
int ECDSA_sign_ver(IN mpz_t r, IN mpz_t s, IN unsigned char *message, IN int messageLength, IN GFP_POINT *publicKey, IN GFP_POINT *p, IN mpz_t order, IN const mpz_t coefficientA, IN const mpz_t prime, IN int hashAlgorithm)
{
	// definition
	int ret = ECC_CRYPTO_FAILED;
	unsigned char *eArray;
	mpz_t e, w, u1, u2;
	gmp_randstate_t state;
	GFP_POINT x, tempValue;

	// initialize
	eArray = (unsigned char *)malloc(eccHashAlgorithm[hashAlgorithm].digestLength);
	mpz_init(e);
	mpz_init(w);
	mpz_init(u1);
	mpz_init(u2);
	gmp_randinit_default(state);
	GFP_init_point(&x);
	GFP_init_point(&tempValue);

	// validation check
	if (hashAlgorithm < 1 || hashAlgorithm > 4) {
		printf("올바른 해쉬 알고리즘을 선택 해 주세요.\n");
		goto end;
	}
	if (r->_mp_size == 0 || s->_mp_size == 0) {
		printf("초기화가 되지 않은 변수를 넣으셨습니다.\n");
		goto end;
	}

	// 1. r과 s가 order보다 작은지 체크
	if (mpz_cmp(r, order) > 0 || mpz_cmp(s, order) > 0) {
		printf("r이나 s가 1부터 n-1 사이에 존재하지 않습니다.\n");
		goto end;
	}

	// 2. compute e = H(m)
	eccHashAlgorithm[hashAlgorithm].digest(message, messageLength, eArray);
	ostr2mpz(e, eArray, messageLength);

	// 3. w = s^(-1) mod n
	mpz_invert(w, s, order);

	// 4. compute u1 = ew mod n, u2 = rw mod n
	mpz_mul_mod(u1, e, w, order);
	mpz_mul_mod(u2, r, w, order);

	// 5. compute X = u1P + u2Q
	GFP_mul_binary_ltor(&x, u1, p, coefficientA, prime);
	GFP_mul_binary_ltor(&tempValue, u2, publicKey, coefficientA, prime);
	GFP_affine_addition(&x, &x, &tempValue, coefficientA, prime);

	// 6. X is infinite
	if (x.isInfinity) {
		goto end;
	}

	// 7. r == x.x
	if (mpz_cmp(x.x, r)) {
		goto end;
	}

	ret = ECC_CRYPTO_SUCCESS;
end:
	// finalize
	free(eArray);
	mpz_clear(e);
	mpz_clear(w);
	mpz_clear(u1);
	mpz_clear(u2);
	gmp_randclear(state);
	GFP_clear_point(&x);
	GFP_clear_point(&tempValue);

	return ret;
}
