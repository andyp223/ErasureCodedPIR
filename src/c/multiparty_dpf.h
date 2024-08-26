#ifndef _MULTIPARTY_DPF_H
#define _MULTIPARTY_DPF_H


void genMultiPartyDPF(EVP_CIPHER_CTX *ctx, int log_domainSize, uint128_t a, uint128_t b, int p, uint8_t*** key_output);
void genOptMultiPartyDPF(EVP_CIPHER_CTX *ctx, int log_domainSize, uint128_t a, uint128_t b, int p, int t, uint8_t*** key_output); 
void genCDDPF(EVP_CIPHER_CTX *ctx, int log_domainSize, uint128_t a, uint128_t b, int p, int t, uint8_t*** key_output); 


void evalAllMultiPartyDPF(EVP_CIPHER_CTX *ctx, int p, int log_domainSize, 
                        uint8_t* key, uint8_t** dataShare);
                        
void evalAllOptMultiPartyDPF(EVP_CIPHER_CTX *ctx, int p, int log_domainSize, 
                        uint8_t* key, int t, uint8_t** dataShare);       

void evalAllOptMultiPartyDPFThread(EVP_CIPHER_CTX *ctx, int p, int log_domainSize, 
                        uint8_t* key, int t, uint8_t** dataShare, int threadIndex, int numThreads);                 

void evalAllCDThread(EVP_CIPHER_CTX *ctx, int p, int log_domainSize, 
                        uint8_t* key, int t, uint8_t** dataShare, int threadIndex, int numThreads);                                         

#endif