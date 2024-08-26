#include <iostream>
#include <iomanip>
#include <string.h>
#include "utils.h"
#include <math.h>
#include <openssl/hmac.h>
// #include <openssl/opensslconf.h>

typedef unsigned __int128 uint128_t;

void handleErrors()
{
  std::cerr << "OpenSSL failure\n";
  abort();
}

void gen_rand_key(unsigned char* buf) {
  if (RAND_bytes(buf, 16) != 1)
    handleErrors();
}

void gen_rand_bytes(unsigned char* buf, int len) {
  if (RAND_bytes(buf, len) != 1)
    handleErrors();
}

void initializeCTX(EVP_CIPHER_CTX *ctx) {
    if(!(ctx = EVP_CIPHER_CTX_new()))
      handleErrors();
}

void mac(uint8_t* key, uint8_t* input, int inputLen, unsigned char* output, int outputLen) {
    HMAC(EVP_sha256(), key, 16, input, inputLen, output, (unsigned int*)(&outputLen));
}


void G(EVP_CIPHER_CTX *ctx, uint8_t* seed, uint32_t plen, unsigned char* output) {
  //EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, seed, NULL))
      handleErrors();

  //plen = (plen + 15) / 16 * 16;
  unsigned char plaintext[plen];
  memset(plaintext, 0, plen);

  if(1 != EVP_EncryptUpdate(ctx, output, &len, plaintext, plen))
      handleErrors();
}

uint32_t blen(uint32_t p) {
  return 16 * 2 + (2 * (p - 1) + 7) / 8;
}

void parse_prg_output(uint8_t* prg_output, uint8_t* seedL, uint8_t* seedR, int* t, uint32_t p) {
    uint32_t len = blen(p); 
    memcpy(seedL, prg_output, 16);
    memcpy(seedR, prg_output + 16, 16);

    for (int i = 32; i < len; i++) {
        uint8_t b = prg_output[i];
        for (int j = 0; j < 2 * (p - 1); j ++) {
            int offset = j / 8; 
            int remainder = j - (8 * offset);
            t[j] = (prg_output[32 + offset] >> remainder) & 1; 
        }
    }
}

void XOR(uint8_t* buf0, uint8_t* buf1, uint8_t* res, uint32_t len) {
  for (int i = 0; i < len; i++) {
    res[i] = buf0[i] ^ buf1[i];
  }
}

int calcDPFTreeKeyLength(int p, int log_domainSize) {
    int CWk_len = (2*p - 2 + 16);
    int CW_len = (p-1) * (2*p - 2 + 16);
    int keyLength = 16 + (log_domainSize * CW_len) + p - 1;
    return keyLength;
}

int calcOptimizedDPFTreeKeyLength(int p, int log_domainSize, int numQueries) {
    int CWk_len = (2*p - 2 + 16);
    int CW_len = (p-1) * (2*p - 2 + 16);
    int keyLength = 16 + (log_domainSize * CW_len) + numQueries*(p - 1);
    return keyLength;
}


int calcMultiPartyDPFKeyLength(int p, int log_domainSize) {
    int n = log_domainSize;
    int domainSize = pow(2, n);
    uint32_t p2 = (uint32_t)(pow(2, p-1)); // store 2^p-1

    uint64_t mu = (uint64_t)ceil((pow(2, n/2.0) * pow(2,(p-1)/2.0)));
    uint64_t nu = (uint64_t)ceil((pow(2,n))/mu);

    int keyLength = 16*p2*nu + p2*mu;
    return keyLength;
}

int calcMultiPartyOptDPFKeyLength(int p, int log_domainSize, int t) {
    int n = log_domainSize;
    int domainSize = pow(2, n);
    int q = (p - t) * choose(p,t) / p;
    uint32_t p2 = (uint32_t)(pow(2, choose(p,t)-1)); // store 2^p-1

    int mu_pow = ceil((double)(n/2));
    uint64_t mu = (uint64_t)pow(2,mu_pow);
    uint64_t nu = (uint64_t)pow(2, n - mu_pow);
    int keyLength = 16*p2*nu + q*nu*p2 + p2*mu;;
    return keyLength;
}

int calcCDDPFKeyLength(int p, int log_domainSize, int t, int num_cd_keys_needed, int num_cd_keys) {
    int n = log_domainSize;
    int domainSize = pow(2, n);
    int q = num_cd_keys;
    uint32_t p2 = (uint32_t)(pow(2, num_cd_keys_needed-1)); // store 2^p-1

    int mu_pow = ceil((double)(n/2)) + 3;
    uint64_t mu = (uint64_t)pow(2,mu_pow);
    uint64_t nu = (uint64_t)pow(2, n - mu_pow);
    int keyLength = 16*p2*nu + q*nu*p2 + p2*mu;
    return keyLength;
}

int calcShamirDPFKeyLength(int log_domainSize) {
    int n = log_domainSize;
    int x = log_domainSize/2 + (log_domainSize % 2 != 0);
    int y = n - x;
    return (int)pow(2,x) + (int)pow(2,y);
}

int calcShamirResponseLength(int log_domainSize, int fileSizeBytes) {
    int n = log_domainSize;
    int x = log_domainSize/2 + (log_domainSize % 2 != 0);
    int y = n - x;
    return ((int)pow(2,x) + (int)pow(2,y) + 2)*fileSizeBytes;
}

int calcWoodruffKeyLength(int p, int b, int t, int logDomainSize, int fileSizeBytes) {
    int d = 2;
    int tmp = d + 1; 
    int numFiles = pow(2,logDomainSize);;
    while (choose(tmp,d) < numFiles) {
        tmp++;
    }
    return tmp; 
}

int getbit(uint128_t x, int n, int b){
	return ((uint128_t)(x) >> (n - b)) & 1;
}

int countNumOnes(uint8_t n) {
    int count = 0;
    while (n) {
        count += n & 1;
        n >>= 1;
    }
    return count;
}

int choose(int n, int k) {
  if (k == 0) {
    return 1;
  } else{
  return (n * choose(n - 1, k - 1)) / k;
  }
}

int get2pow(int pow) {
    int output = 1; 
    int base = 2;
    while (pow > 0) {
        if (pow & 1 == 1) // y is odd
        {
            output = output * base;
        }
        base = base * base;
        pow = pow >> 1; // y=y/2;
    }
    return output;
}


void print_seed(uint8_t* seed) {
  for (int i = 0; i < 16; ++i) {
    printf("%d", seed[i]);
    printf(",");
  }
  std::cout << "\n";
}

void print_key(uint8_t* key, int keyLength) {
  for (int i = 0; i < keyLength; i++) {
    printf("%d,",key[i]);
  }
  printf("\n");
}

void print_prg_output(uint8_t* prg_output, int p) {
  for (int i = 0; i < blen(p); ++i) {
    printf("%d", prg_output[i]);
    printf(",");
  }
  std::cout << "\n";
}

void printBuffer(uint8_t *buf, int len) {
    for (int i = 0; i < len; i++) {
        printf("%d,", buf[i]);
    }
    printf("\n");
}

uint128_t convertInt(int x){
  return (uint128_t)(x);
}