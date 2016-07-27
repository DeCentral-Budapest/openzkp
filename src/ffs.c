#include "ffs.h"

#define BN_negate(x) ((x)->neg = (!((x)->neg)) & 1)

void rand_negate(BIGNUM *bn)
{

	unsigned char rand;
	RAND_bytes(&rand, 1);
	if((const char[]){0,1}[rand%2])
	{
		BN_negate(bn);
	}
}

void make_equivalent_modulo(BIGNUM *bn, BIGNUM *n, BN_CTX *bn_ctx)
{
	BIGNUM *modulus_rand = BN_new();
	BN_rand(modulus_rand, 128, 0, 0);
	rand_negate(modulus_rand);
	BN_mul(modulus_rand, modulus_rand, n, bn_ctx);
	BN_add(bn, bn, modulus_rand);
	BN_free(modulus_rand);
}


FFS_CTX *FFS_CTX_new(long k, BN_CTX *bn_ctx)
{
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *n = BN_new();
	BN_generate_prime_ex(p, 2048, 0, 0, 0, 0);
	BN_generate_prime_ex(q, 2048, 0, 0, 0, 0);
	BN_mul(n, p, q, bn_ctx);
	FFS_CTX *ret = malloc(sizeof(FFS_CTX*));
	if (ret != 0)
	{
		ret->bn_ctx = bn_ctx;
		ret->n = n;
		ret->k = k;
	}
	return ret;
}

FFS_Prover *FFS_Prover_new(BIGNUM **s, FFS_CTX *ctx)
{
	FFS_Prover *ret = malloc(sizeof(FFS_Prover*));
	if(ret == 0)
	{
		fprintf(stderr, "Failed to allocate memory for prover!\n");
		return 0;
	}
	ret->ctx = ctx;
	if (s == 0)
	{
		ret->s = malloc(sizeof(BIGNUM*)*ctx->k);
	}
	else
	{
		ret->s = s;
	}
	return ret;
}

FFS_Verifier *FFS_Verifier_new(BIGNUM **v, FFS_CTX *ctx)
{
	FFS_Verifier *ret = malloc(sizeof(FFS_Verifier*));
	if(ret == 0)
	{
		fprintf(stderr, "Failed to allocate memory for verifier!\n");
		return 0;
	}
	ret->ctx = ctx;
	ret->v = v;
	return ret;
}

BIGNUM **FFS_generate_secret(FFS_Prover *prover)
{
	BIGNUM **ret = malloc(sizeof(BIGNUM*)*(prover->ctx->k+1));
	long i;
	BIGNUM *gcd = BN_new();
	for (i=0; i<prover->ctx->k; i++)
	{
		prover->s[i] = BN_new();
		unsigned char coprime_flag = 0;
		while(!coprime_flag)
		{
			BN_rand(prover->s[i], 256, 0, 0);
			BN_gcd(gcd, prover->s[i], prover->ctx->n, prover->ctx->bn_ctx);
			coprime_flag = BN_is_one(gcd);
		}
		ret[i] = BN_new();
		BN_one(ret[i]);
		BN_sqr(ret[i], ret[i], prover->ctx->bn_ctx);
		make_equivalent_modulo(ret[i], prover->ctx->n, prover->ctx->bn_ctx);
	}
	BN_free(gcd);
	return ret;
}


BIGNUM **FFS_generate_challenge(FFS_Prover *prover)
{
	BIGNUM **ret = malloc(sizeof(BIGNUM*)*prover->ctx->k);
	if(ret==0)
	{
		fprintf(stderr, "Failed to allocate memory for challenge!\n");
		return 0;
	}
	long i;
	for(i=0; i<prover->ctx->k; i++)
	{
		ret[i] = BN_new();
		BN_sqr(ret[i], prover->s[i], prover->ctx->bn_ctx);
		make_equivalent_modulo(ret[i], prover->ctx->n, prover->ctx->bn_ctx);
	}
	return ret;
}

BIGNUM *FFS_proof_nonce(FFS_Prover *prover)
{
	BIGNUM *ret = BN_new();
	prover->r = BN_new();
	BN_rand(prover->r, 128, 0, 0);
	BN_sqr(ret, prover->r, prover->ctx->bn_ctx);
	make_equivalent_modulo(ret, prover->ctx->n, prover->ctx->bn_ctx);
	return ret;
}

unsigned char *FFS_verification_nonce(FFS_Verifier *verifier)
{
	unsigned char *ret = malloc(sizeof(unsigned char*)*verifier->ctx->k);
	if(ret==0)
	{
		fprintf(stderr, "Failed to allocate memory for verification!\n");
		return 0;
	}
	long i;
	for (i=0; i<verifier->ctx->k; i++)
	{
		unsigned char rand;
		RAND_bytes(&rand, 1);
		ret[i] = (const unsigned char[]){0,1}[rand % 2];
	}
	return ret;
}

BIGNUM *FFS_Prove(FFS_Prover *prover, unsigned char *vvector)
{
	BIGNUM *ret = BN_new();
	BN_one(ret);
	BIGNUM *res_exp = BN_new();
	BIGNUM *exp = BN_new();
	long i;
	for(i=0; i<prover->ctx->k; i++)
	{
		BN_set_word(exp, vvector[i]);
		BN_exp(res_exp, prover->s[i], exp, prover->ctx->bn_ctx);
		BN_mul(ret, ret, res_exp, prover->ctx->bn_ctx);
	}
	BN_mul(ret, ret, prover->r, prover->ctx->bn_ctx);
	make_equivalent_modulo(ret, prover->ctx->n, prover->ctx->bn_ctx);
	return ret;
}

double FFS_Verify(FFS_Verifier *verifier, BIGNUM *proof, BIGNUM *proof_nonce, unsigned char *verification_nonce)
{
	double ret = 0.0;
	BIGNUM *exp = BN_new();
	BIGNUM *res_exp = BN_new();
	BIGNUM *v = BN_new();
	BN_one(v);
	long i;
	for(i=0; i<verifier->ctx->k; i++)
	{
		BN_set_word(exp, verification_nonce[i]);
		BN_exp(res_exp, verifier->v[i], exp, verifier->ctx->bn_ctx);
		BN_mul(v, v, res_exp, verifier->ctx->bn_ctx);
	}
	BN_mul(v, v, proof_nonce, verifier->ctx->bn_ctx);

	BIGNUM *y = BN_new();
	BN_sqr(y, proof, verifier->ctx->bn_ctx);
	BIGNUM *y_mod_n = BN_new();
	BIGNUM *v_mod_n = BN_new();
	BN_nnmod(y_mod_n, y, verifier->ctx->n, verifier->ctx->bn_ctx);
	BN_nnmod(v_mod_n, v, verifier->ctx->n, verifier->ctx->bn_ctx);
	if(!BN_ucmp(y_mod_n, v_mod_n))
	{
		ret = 1-(1.0/pow(2, verifier->ctx->k));
	}
	return ret;
}

