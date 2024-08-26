#ifndef _DPF_TREE_H
#define _DPF_TREE_H

#ifndef SWIG
    typedef unsigned __int128 uint128_t;
#endif

void genDPF(EVP_CIPHER_CTX *ctx, int log_domainSize, uint128_t index, int dataSize, 
                        std::vector<uint8_t> finalCW_values, int p, uint8_t*** key_output);

void evalDPF(EVP_CIPHER_CTX *ctx, int p, int party_index, int log_domainSize, 
                        uint8_t* key, uint128_t index, int dataSize, uint8_t* result);

void evalAllDPF(EVP_CIPHER_CTX *ctx, int p, int party_index, int log_domainSize, 
                        uint8_t* key, int dataSize, uint8_t** dataShare);


void genOptimizedDPF(EVP_CIPHER_CTX *ctx, int log_domainSize, uint128_t index, int dataSize, 
                        std::vector<uint8_t> finalCW_values, int p, int numQueries, uint8_t*** key_output);

void evalAllOptimizedDPF(EVP_CIPHER_CTX *ctx, int p, int party_index, int log_domainSize, 
                        uint8_t* key, int dataSize, int numQueries, uint8_t** dataShare);                        
void evalAllOptimizedDPFThread(EVP_CIPHER_CTX *ctx, int p, int party_index, int log_domainSize, 
                        uint8_t* key, int dataSize, int numQueries, uint8_t** dataShare, 
                        int threadNum, int numThreads);


#endif 