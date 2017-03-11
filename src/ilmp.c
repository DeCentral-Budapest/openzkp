#include "ilmp.h"
#include <stdio.h>

BIGNUM **ILMP_init_commitment(BIGNUM **s1, BIGNUM **s2, size_t len, BN_CTX *ctx)
{
  if (s1 == 0 || s2 == 0)
  {
    fprintf(stderr, "commitment numbers cannot be NULL\n");
    return 0;
  }
  BIGNUM **ret = malloc((len-1)*sizeof(BIGNUM));
  BIGNUM **theta = malloc((len-1)*sizeof(BIGNUM));

  size_t i;
  for(i=0; i<len-1; i++)
  {
    theta[i] = BN_new();
    ret[i] = BN_new();
    BN_rand(theta[i], 256, 0, 0);
    BN_print_fp(stdout, theta[i]);
  }

  //TODO optimize this
  BN_exp(ret[0], s2[0], theta[0], ctx);
  BIGNUM *t1 = BN_new();
  BIGNUM *t2 = BN_new();
  for(i=1; i<len-1; i++)
  {
    printf("iteration %d/%d", i, len-1); //no output at all? O.o
    BN_exp(t1, s1[i], theta[i-1], ctx);
    BN_exp(t2, s2[i], theta[i], ctx);
    BN_mul(ret[i], t1, t2, ctx);
  }
  BN_exp(ret[len-1], s1[len-1], theta[len-2], ctx);

  return ret;

}

BIGNUM *ILMP_init_challenge()
{
  BIGNUM *ret = BN_new();
  BIGNUM *q = BN_new();
  BN_hex2bn(&q, ZKP_MODEX_Q);
  BN_rand_range(ret, q);
  return ret;
}

BIGNUM **ILMP_final(BIGNUM **s1, BIGNUM **s2, BIGNUM **commitment, BIGNUM *challenge, size_t len, BN_CTX *ctx)
{
  BIGNUM **ret = malloc((len-1)*sizeof(BIGNUM));
  int i, j;
  BIGNUM *y = BN_dup(challenge);
  BIGNUM *t1 = BN_new();
  for (i = 0; i<len; i++)
  {      
    y->neg = (len-i-1) % 2;

    for(j=i+1; j<len; j++)
    {
      BN_div(t1, s2[i], s1[i], 0, ctx);
    }
    BN_mul(ret[i], y, t1, ctx);
  }
  return ret;
}
