#ifndef OPENZKP_PEDERSEN_H
#define OPENZKP_PEDERSEN_H
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <math.h>
#include "modp.h"


BIGNUM **ILMP_init_commitment(BIGNUM **s1, BIGNUM **s2, size_t len, BN_CTX *ctx);
extern BIGNUM *ILMP_init_challenge();
extern BIGNUM **ILMP_final(BIGNUM **s1, BIGNUM **s2, BIGNUM **commitment, BIGNUM *challenge, size_t len, BN_CTX *ctx);

#endif
