// gcc -o ilmp ilmp.c -lzkp -lcrypto -lm
#include <openzkp/ilmp.h>
#include <stdio.h>
int main()
{
  fprintf(stdout, "ASD");
	BN_CTX *bn_ctx = BN_CTX_new();
  //our secrets
  BIGNUM **s1 = malloc(8*sizeof(BIGNUM)); //these are already in the form of log(g,secret)
  BIGNUM **s2 = malloc(8*sizeof(BIGNUM));
  unsigned short i;
  for(i=0; i<8; i++)
  {
    BN_hex2bn(&s1[i], "deadbeef");
    BN_hex2bn(&s2[i], "feebdead");
  }
  BIGNUM **commitment = ILMP_init_commitment(s1, s2, 8, bn_ctx);
  BIGNUM *challenge = ILMP_init_challenge();

  //prover sends this solution over TCP or any other means
  BIGNUM **prover_solution = ILMP_final(s1,s2,commitment,challenge,8,bn_ctx);

  //verifier repeats the final step
  BIGNUM **verifier_solution = ILMP_final(s1,s2,commitment,challenge,8,bn_ctx);

  for(i=0; i<8; i++)
  {
    if(BN_cmp(prover_solution[i], verifier_solution[i]) != 0)
    {
      fprintf(stderr, "validation failed!");
      return 1;
    }
  }
	printf("identity validated");
	return 0;
}
