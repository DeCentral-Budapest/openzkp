// gcc -o ilmp ilmp.c -lzkp -lcrypto -lm
#include <stdio.h>
#include <openzkp/ilmp.h>
int main()
{
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
  
  if(prover_solution==0)
  {
    return 1;
  }

  //verifier repeats the final step
  BIGNUM **verifier_solution = ILMP_final(s1,s2,commitment,challenge,8,bn_ctx);
  
  if(verifier_solution==0)
  {
    return 2;
  }

  for(i=0; i<8; i++)
  {
    printf("\np: ");
    BN_print_fp(stdout, prover_solution[i]);
    printf("\n");
    printf("v: ");
    BN_print_fp(stdout, verifier_solution[i]);
    printf("\n");
    return 2;
    if(BN_cmp(prover_solution[i], verifier_solution[i]) != 0)
    {
      fprintf(stderr, "validation failed!");
      return 1;
    }
  }
	printf("identity validated");
	return 0;
}
