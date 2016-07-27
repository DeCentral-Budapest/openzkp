#ifndef OPENZKP_FFS_H
#define OPENZKP_FFS_H

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

typedef struct {
BN_CTX *bn_ctx;
BIGNUM *n;
long k;
} FFS_CTX;

typedef struct {
	FFS_CTX *ctx;
	BIGNUM **s;
	BIGNUM *r;
} FFS_Prover;

typedef struct {
	FFS_CTX *ctx;
	BIGNUM **v;
} FFS_Verifier;

extern FFS_CTX *FFS_CTX_new(long k, BN_CTX *ctx);
extern FFS_Prover *FFS_Prover_new(BIGNUM **s, FFS_CTX *ctx);
extern FFS_Verifier *FFS_Verifier_new(BIGNUM **v, FFS_CTX *ctx);
extern BIGNUM **FFS_generate_secret(FFS_Prover *prover);
extern BIGNUM **FFS_generate_challenge(FFS_Prover *prover);
extern BIGNUM *FFS_proof_nonce(FFS_Prover *prover);
extern unsigned char *FFS_verification_nonce(FFS_Verifier *verifier);
extern BIGNUM *FFS_Prove(FFS_Prover *prover, unsigned char *verification_nonce);
extern double FFS_Verify(FFS_Verifier *verifier, BIGNUM *proof, BIGNUM *proof_nonce, unsigned char *verification_nonce);
#endif
