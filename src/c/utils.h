#ifndef _UTILS_H
#define _UTILS_H

#include <vector>
//#include "openssl-aes.h"
//#include <cpuid.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>


#ifndef SWIG
    typedef unsigned __int128 uint128_t;
#endif

// Generate random AES key
void gen_rand_key(unsigned char* buf);
// PRG
void initializeCTX(EVP_CIPHER_CTX *ctx);
void G(EVP_CIPHER_CTX *ctx, uint8_t* seed, uint32_t plen, unsigned char* output);
void mac(uint8_t* key, uint8_t* input, int inputLen, unsigned char* output, int outputLen);

int calcDPFTreeKeyLength(int p, int log_domainSize);
int calcMultiPartyDPFKeyLength(int p, int log_domainSize);
int calcOptimizedDPFTreeKeyLength(int p, int log_domainSize, int numQueries);
int calcMultiPartyOptDPFKeyLength(int p, int log_domainSize, int t); 
int calcCDDPFKeyLength(int p, int log_domainSize, int t, int num_cd_keys_needed, int num_cd_keys); 
int calcShamirDPFKeyLength(int log_domainSize);
int calcShamirResponseLength(int log_domainSize, int fileSizeBytes);
int calcWoodruffKeyLength(int p, int r, int t, int logDomainSize, int fileSizeBytes);

uint32_t blen(uint32_t p);
void parse_prg_output(uint8_t* prg_output, uint8_t* seedL, uint8_t* seedR, int* t, uint32_t p);
void XOR(uint8_t* buf0, uint8_t* buf1, uint8_t* res, uint32_t len);
void gen_rand_bytes(unsigned char* buf, int len);
/* Debug Use */

int countNumOnes(uint8_t n);
int getbit(uint128_t x, int n, int b);
int choose(int n, int k);
int get2pow(int pow);

void print_seed(uint8_t* seed);
void print_key(uint8_t* key, int keyLength);
void print_prg_output(uint8_t* prg_output, int p);
void printBuffer(uint8_t *buf, int len);
uint128_t convertInt(int x);

// std::vector<std::vector<int>>makeCombi(int n, int k);
#endif