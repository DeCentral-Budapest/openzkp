#ifndef OPENZKP_PEDERSEN_H
#define OPENZKP_PEDERSEN_H
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <math.h>
#include <modp.h>


extern unsigned char *ILMP_init_commitment(unsigned char *s1, unsigned char *s2, size_t len);
