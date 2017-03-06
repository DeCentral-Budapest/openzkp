#include "chaum_pedersen.h"


BIGNUM **ILMP_init_commitment(unsigned char *s1, unsigned char *s2, size_t len)
{
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM **ret = malloc((len-1)*sizeof(BIGNUM));
  BIGNUM **theta = malloc((len-1)*sizeof(BIGNUM));
  size_t i;
  for(i=0; i<len-1; i++)
  {
    theta[i] = BN_new();
    BN_rand(theta[i], 256, 0, 0);
  }

  //TODO optimize this
  BN_exp(ret[0], s2[0], theta[0], ctx);
  BIGNUM *t1 = BN_new();
  BIGNUM *t2 = BN_new();
  for(i=1; i<len-1; i++)
  {
    BN_exp(t1, s1[i], theta[i-1], ctx);
    BN_exp(t2, s2[i], theta[i], ctx);
    BN_mul(ret[i], t1, t2, ctx);
  }
  BN_exp(ret[len], s1[len], theta[len-1], ctx);

  return ret;

}

BIGNUM *ILMP_init_challenge(ILMP_CTX *ctx)
{
  BIGNUM *ret = BN_new();
  BN_rand_range(ret, ZKP_MODEX_Q);
  return ret;
}

BIGNUM **ILMP_prove(BIGNUM **s1, BIGNUM **s2, BIGNUM **commitment, BIGNUM *challenge, size_t len, BN_CTX *ctx)
{
  BIGNUM **ret = malloc((len-1)*sizeof(BIGNUM));
  int i, j;
  BIGNUM *y = BN_dup(challenge);
  BIGNUM *t1 = BN_new();
  for (i = 0; i<len; i++)
  {      
    y->neg = (k-i-1) % 2;
    
    for(j=i+1; j<k; j++)
    {
      BN_div(t1, s2, s1, ctx);
    }
    BN_mul(ret[i], y, t1, ctx);
  }
  return ret;
}

int ILMP_validate(BIGNUM **s1, BIGNUM **s2,BIGNUM **solution, BIGNUM *challenge, size_t len, BN_CTX *ctx)
{
  //TODO, maybe make more generic with merging with the function above?
}
