// gcc -o ffs ffs.c -lzkp -lcrypto -lm
#include <openzkp/ffs.h>
int main()
{
	BN_CTX *bn_ctx = BN_CTX_new();
	FFS_CTX *ctx = FFS_CTX_new(1024, bn_ctx);
	FFS_Prover *peggy = FFS_Prover_new(0, ctx);
	BIGNUM **s = FFS_generate_secret(peggy);
	BIGNUM **v = FFS_generate_challenge(peggy);
	FFS_Verifier *victor = FFS_Verifier_new(v, ctx);
	BIGNUM *proof_nonce = FFS_proof_nonce(peggy);
	unsigned char *verification_nonce = FFS_verification_nonce(victor);

	BIGNUM *proof = FFS_Prove(peggy, verification_nonce);
	double confidence = FFS_Verify(victor, proof, proof_nonce, verification_nonce);
	printf("identity validated with %.4f%% confidence\n", 100*confidence);
	/* cleanup */
	free(s);
	free(v);
	free(peggy);
	free(proof);
	free(proof_nonce);
	free(victor);
	free(verification_nonce);
	free(ctx);
	return 0;
}
