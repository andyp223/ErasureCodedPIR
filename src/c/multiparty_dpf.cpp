#include <iostream>
#include <cassert>
#include <cstring>
#include <math.h>     
#include "utils.h"
#include "params.h"
#include "multiparty_dpf.h"

typedef unsigned __int128 uint128_t;

void genMultiPartyDPF(EVP_CIPHER_CTX *ctx, int log_domainSize, uint128_t a, uint128_t b, int p, uint8_t*** key_output) {
    int n = log_domainSize;
    uint32_t p2 = (uint32_t)(pow(2, p-1));
    uint64_t mu = (uint64_t)ceil((pow(2, n/2.0) * pow(2,(p-1)/2.0)));
    uint64_t nu = (uint64_t)ceil((pow(2,n))/mu);

    uint32_t delta = a & ((1 << (n/2)) - 1);
    uint32_t gamma = (a & (((1 << (n+1)/2) - 1) << n/2)) >> n/2;

    unsigned char*** aArr = (unsigned char***) malloc(sizeof(unsigned char**)*nu);
    for (int i = 0; i < nu; i++) {
        aArr[i] = (unsigned char**) malloc(sizeof(unsigned char*)*p);
        for (int j = 0; j < p; j++) {
            aArr[i][j] = (unsigned char*) malloc(p2);
        }
    }
    for (int i = 0; i < nu; i++) {
        for (int j = 0; j < p; j++) {
            if (j != (p-1)) {
                gen_rand_bytes(aArr[i][j],p2);
                for (int k = 0; k < p2; k++) {
                    aArr[i][j][k] = aArr[i][j][k] % 2;
                }
            } else {
                // Set the last row so that the columns have odd or even number
                // of bits
                for (int k = 0; k < p2; k++) {
                    uint32_t curr_bits = 0;
                    for (int l = 0; l < p-1; l++) {
                        curr_bits += aArr[i][l][k];
                    }
                    curr_bits = curr_bits % 2;
                    // If array index is not gamma, just make sure the p's sum up to even
                    if (i != gamma) {
                        aArr[i][j][k] = (curr_bits == 0) ? 0 : 1; 
                    } else {
                        // Make sure the array at gamma are odd binaries
                        aArr[i][j][k] = (curr_bits == 0) ? 1 : 0; 
                    }
                }
            }
        }
    }
    uint128_t** s = (uint128_t**) malloc(sizeof(uint128_t*) * nu);
    for (int i = 0; i < nu; i++) {
        s[i] = (uint128_t*) malloc(16*p2);
        for (int j = 0; j < p2; j++) {
            gen_rand_key((uint8_t*)&s[i][j]);
        }
    }

    //uint8_t m_bytes = mu; // PRG size 
    uint8_t** cw = (uint8_t**) malloc(sizeof(uint8_t*)*p2);
    for (int i = 0; i < p2; i++) {
        cw[i] = (uint8_t*)malloc(mu);
    }

    uint8_t* cw_temp = (uint8_t*) malloc(mu); // stores the last "special" cw
    memset(cw_temp, 0, mu); 

    // key length = 16 * 2^{p-1}*nu + 2^{p-1}*m*mu 
    for (int i = 0; i < p2; i++) {
        unsigned char* tmp = (unsigned char*)malloc(mu);
        G(ctx, (uint8_t*)&s[gamma][i], mu, tmp);
        XOR(cw_temp,tmp,cw_temp,mu);

        if (i != p2 - 1) {
            gen_rand_bytes(cw[i],mu);
            XOR(cw_temp,cw[i],cw_temp,mu);
        }
        free(tmp);
    }

    // format the last "special" cw
    for (int i = 0; i < mu; i++) {
        cw[p2 - 1][i] = (i == delta) ? b ^ cw_temp[i] : cw_temp[i];
    }

    free(cw_temp);
    int keyLength = 16*p2*nu + p2*mu;
    int sigmaLength = 16*p2;

    uint8_t* buff[p]; 
    
    for (int i = 0; i < p; i++) {
        buff[i] = (uint8_t*) malloc(keyLength); 
        for (int j = 0; j < nu; j++) {
            for (int k = 0; k < p2; k++) {
                if (aArr[j][i][k] == 0) {
                    memset(&buff[i][j*sigmaLength + 16*k],0,16);
                }else {
                    assert(aArr[j][i][k] == 1);
                    memcpy(&buff[i][j*sigmaLength + 16*k],&s[j][k],16);
                }
            }
        }
        for (int j = 0; j < p2; j++) {
            memcpy(&buff[i][nu*sigmaLength + j*mu],cw[j],mu);
        }
    }


    for (int i = 0 ; i < p; i++) {
        memcpy((*key_output)[i],buff[i],keyLength);
        free(buff[i]);
    }

    // Free memory 
    for (int i = 0; i < nu; i++) {
        for (int j = 0; j < p; j++) {
            free(aArr[i][j]);
        }
        free(aArr[i]);
    }

    free(aArr);
    for (int i = 0; i < nu; i++) {
        free(s[i]);
    }
    free(s);
}

void genOptMultiPartyDPF(EVP_CIPHER_CTX *ctx, int log_domainSize, uint128_t a, uint128_t b, int p, int t, uint8_t*** key_output) {
    int n = log_domainSize;
    int q = choose(p,t);

    uint32_t p2 = (uint32_t)(pow(2, q-1));
    int mu_pow = ceil(log2(ceil((pow(2, n/2.0) * pow(2,(p-1)/2.0)))));
    uint64_t mu = (uint64_t)pow(2,mu_pow);
    uint64_t nu = (uint64_t)pow(2, n - mu_pow);

    uint32_t delta = a & ((1 << (n/2)) - 1);
    uint32_t gamma = (a & (((1 << (n+1)/2) - 1) << n/2)) >> n/2;

    unsigned char*** aArr = (unsigned char***) malloc(sizeof(unsigned char**)*nu);
    for (int i = 0; i < nu; i++) {
        aArr[i] = (unsigned char**) malloc(sizeof(unsigned char*)*q);
        for (int j = 0; j < q; j++) {
            aArr[i][j] = (unsigned char*) malloc(p2);
        }
    }

    for (int i = 0; i < nu; i++) {
        for (int j = 0; j < q; j++) {
            if (j != (q-1)) {
                gen_rand_bytes(aArr[i][j],p2);
                for (int k = 0; k < p2; k++) {
                    aArr[i][j][k] = aArr[i][j][k] % 2;
                }
            } else {
                for (int k = 0; k < p2; k++) {
                    uint32_t curr_bits = 0;
                    for (int l = 0; l < q-1; l++) {
                        curr_bits += aArr[i][l][k];
                    }
                    curr_bits = curr_bits % 2;
                    // If array index is not gamma, just make sure the p's sum up to even
                    if (i != gamma) {
                        aArr[i][j][k] = (curr_bits == 0) ? 0 : 1; 
                    } else {
                        // Make sure the array at gamma are odd binaries
                        aArr[i][j][k] = (curr_bits == 0) ? 1 : 0; 
                    }
                }
            }
        }
    }

    uint128_t** s = (uint128_t**) malloc(sizeof(uint128_t*) * nu);
    for (int i = 0; i < nu; i++) {
        s[i] = (uint128_t*) malloc(16*p2);
        for (int j = 0; j < p2; j++) {
            gen_rand_key((uint8_t*)&s[i][j]);
        }
    }

    uint8_t** cw = (uint8_t**) malloc(sizeof(uint8_t*)*p2);
    for (int i = 0; i < p2; i++) {
        cw[i] = (uint8_t*)malloc(mu);
    }

    uint8_t* cw_temp = (uint8_t*) malloc(mu); // stores the last "special" cw
    memset(cw_temp, 0, mu); 
    for (int i = 0; i < p2; i++) {
        unsigned char* tmp = (unsigned char*)malloc(mu);
        G(ctx, (uint8_t*)&s[gamma][i], mu, tmp);
        XOR(cw_temp,tmp,cw_temp,mu);

        if (i != p2 - 1) {
            gen_rand_bytes(cw[i],mu);
            XOR(cw_temp,cw[i],cw_temp,mu);
        }
        free(tmp);
    }

    // format the last "special" cw
    for (int i = 0; i < mu; i++) {
        cw[p2 - 1][i] = (i == delta) ? b ^ cw_temp[i] : cw_temp[i];
    }
    free(cw_temp);
    int keyLength = calcMultiPartyOptDPFKeyLength(p,log_domainSize,t);
    int sigmaLength = 16*p2;

    uint8_t* buff[p]; 
    uint8_t** seedsToggle = (uint8_t**)malloc(nu*sizeof(uint8_t*));
    for (int i = 0; i < nu; i++) {
        seedsToggle[i] = (uint8_t*)malloc(p2);
    }
    for (int i = 0; i < p; i++) {
        for (int j = 0; j < nu; j++) {
            memset(seedsToggle[j],0,p2);
        }

        buff[i] = (uint8_t*) malloc(keyLength); 

        for (int k = 0; k < RSS_SUBSETS[i].size(); k++) {
            int currInd = RSS_SUBSETS[i][k];
            for (int a = 0; a < nu; a++) {
                for (int b = 0; b < p2; b++) {
                    seedsToggle[a][b] = seedsToggle[a][b] || aArr[a][currInd][b];
                    buff[i][16*(p2*nu) + k*(nu*p2) + a*p2 + b] = aArr[a][currInd][b];
                }
            }
        }
        for (int j = 0; j < nu; j++) {
            for (int k = 0; k < p2; k++) {
                if (seedsToggle[j][k] == 0) {
                    memset(&buff[i][j*sigmaLength + 16*k],0,16);
                }else {
                    assert(seedsToggle[j][k] == 1);
                    memcpy(&buff[i][j*sigmaLength + 16*k],&s[j][k],16);
                }
            }
        }
        for (int j = 0; j < p2; j++) {
            memcpy(&buff[i][nu*sigmaLength + NUM_RSS_KEYS*nu*p2 + j*mu],cw[j],mu);
        }
    }

    for (int i = 0 ; i < p; i++) {
        memcpy((*key_output)[i],buff[i],keyLength);
        free(buff[i]);
    }

    // Free memory 
    for (int i = 0; i < nu; i++) {
        free(seedsToggle[i]);
    }
    free(seedsToggle);

    for (int i = 0; i < nu; i++) {
        for (int j = 0; j < p; j++) {
            free(aArr[i][j]);
        }
        free(aArr[i]);
    }

    free(aArr);
    for (int i = 0; i < nu; i++) {
        free(s[i]);
    }
    free(s);
}

void genCDDPF(EVP_CIPHER_CTX *ctx, int log_domainSize, uint128_t a, uint128_t b, int p, int t, uint8_t*** key_output) {
    int n = log_domainSize;
    int q = NUM_CD_KEYS_NEEDED;
    uint32_t p2 = (uint32_t)(pow(2, q-1));
    int mu_pow = ceil((double)(n/2))+ 3;
    uint64_t mu = (uint64_t)pow(2,mu_pow);
    uint64_t nu = (uint64_t)pow(2, n - mu_pow);

    uint32_t delta = a & ((1 << (n/2)) - 1);
    uint32_t gamma = (a & (((1 << (n+1)/2) - 1) << n/2)) >> n/2;

    unsigned char*** aArr = (unsigned char***) malloc(sizeof(unsigned char**)*nu);
    for (int i = 0; i < nu; i++) {
        aArr[i] = (unsigned char**) malloc(sizeof(unsigned char*)*q);
        for (int j = 0; j < q; j++) {
            aArr[i][j] = (unsigned char*) malloc(p2);
        }
    }

    for (int i = 0; i < nu; i++) {
        for (int j = 0; j < q; j++) {
            if (j != (q-1)) {
                gen_rand_bytes(aArr[i][j],p2);
                for (int k = 0; k < p2; k++) {
                    aArr[i][j][k] = aArr[i][j][k] % 2;
                }
            } else {
                // Set the last row so that the columns have odd or even number
                // of bits
                for (int k = 0; k < p2; k++) {
                    uint32_t curr_bits = 0;
                    for (int l = 0; l < q-1; l++) {
                        curr_bits += aArr[i][l][k];
                    }
                    curr_bits = curr_bits % 2;
                    // If array index is not gamma, just make sure the p's sum up to even
                    if (i != gamma) {
                        aArr[i][j][k] = (curr_bits == 0) ? 0 : 1; 
                    } else {
                        // Make sure the array at gamma are odd binaries
                        aArr[i][j][k] = (curr_bits == 0) ? 1 : 0; 
                    }
                }
            }
        }
    }

    uint128_t** s = (uint128_t**) malloc(sizeof(uint128_t*) * nu);
    for (int i = 0; i < nu; i++) {
        s[i] = (uint128_t*) malloc(16*p2);
        for (int j = 0; j < p2; j++) {
            gen_rand_key((uint8_t*)&s[i][j]);
        }
    }

    uint8_t** cw = (uint8_t**) malloc(sizeof(uint8_t*)*p2);
    for (int i = 0; i < p2; i++) {
        cw[i] = (uint8_t*)malloc(mu);
    }

    uint8_t* cw_temp = (uint8_t*) malloc(mu); // stores the last "special" cw
    memset(cw_temp, 0, mu);  
    for (int i = 0; i < p2; i++) {
        unsigned char* tmp = (unsigned char*)malloc(mu);
        G(ctx, (uint8_t*)&s[gamma][i], mu, tmp);
        XOR(cw_temp,tmp,cw_temp,mu);

        if (i != p2 - 1) {
            gen_rand_bytes(cw[i],mu);
            XOR(cw_temp,cw[i],cw_temp,mu);
        }
        free(tmp);
    }

    // format the last "special" cw
    for (int i = 0; i < mu; i++) {
        cw[p2 - 1][i] = (i == delta) ? b ^ cw_temp[i] : cw_temp[i];
    }
    free(cw_temp);
    int keyLength = calcCDDPFKeyLength(p,log_domainSize,t,NUM_CD_KEYS_NEEDED,NUM_CD_KEYS);
    int sigmaLength = 16*p2;

    uint8_t* buff[p]; 
    uint8_t** seedsToggle = (uint8_t**)malloc(nu*sizeof(uint8_t*));
    for (int i = 0; i < nu; i++) {
        seedsToggle[i] = (uint8_t*)malloc(p2);
    }
    for (int i = 0; i < p; i++) {
        for (int j = 0; j < nu; j++) {
            memset(seedsToggle[j],0,p2);
        }

        buff[i] = (uint8_t*) malloc(keyLength); 
        for (int k = 0; k < CD_SUBSETS[i].size(); k++) {
            int currInd = CD_SUBSETS[i][k];
            for (int a = 0; a < nu; a++) {
                for (int b = 0; b < p2; b++) {
                    seedsToggle[a][b] = seedsToggle[a][b] || aArr[a][currInd][b];
                    buff[i][16*(p2*nu) + k*(nu*p2) + a*p2 + b] = aArr[a][currInd][b];
                }
            }
        }
        for (int j = 0; j < nu; j++) {
            for (int k = 0; k < p2; k++) {
                if (seedsToggle[j][k] == 0) {
                    memset(&buff[i][j*sigmaLength + 16*k],0,16);
                }else {
                    assert(seedsToggle[j][k] == 1);
                    memcpy(&buff[i][j*sigmaLength + 16*k],&s[j][k],16);
                }
            }
        }
        for (int j = 0; j < p2; j++) {
            memcpy(&buff[i][nu*sigmaLength + NUM_CD_KEYS*nu*p2 + j*mu],cw[j],mu);
        }
    }

    for (int i = 0 ; i < p; i++) {
        memcpy((*key_output)[i],buff[i],keyLength);
        free(buff[i]);
    }

    // Free memory 
    for (int i = 0; i < nu; i++) {
        free(seedsToggle[i]);
    }
    free(seedsToggle);
    free(aArr);
    for (int i = 0; i < nu; i++) {
        free(s[i]);
    }
    free(s);
}


void evalAllMultiPartyDPF(EVP_CIPHER_CTX *ctx, int p, int log_domainSize, 
                        uint8_t* key, uint8_t** dataShare) {
    int n = log_domainSize;
    int domainSize = pow(2, n);
    uint32_t p2 = (uint32_t)(pow(2, p-1)); // store 2^p-1

    uint64_t mu = (uint64_t)ceil((pow(2, n/2.0) * pow(2,(p-1)/2.0)));
    uint64_t nu = (uint64_t)ceil((pow(2,n))/mu);

    int keyLength = 16*p2*nu + p2*mu;
    int sigmaLength = 16*p2;

    // copy s and cw into arrays
    uint128_t** s = (uint128_t**) malloc(sizeof(uint128_t*) * nu);
    for (int i = 0; i < nu; i++) {
        s[i] = (uint128_t*) malloc(16*p2);
        for (int j = 0; j < p2; j++) {
            memcpy(&s[i][j], &key[i*sigmaLength + 16*j], 16);
        }
    }

    //uint8_t m_bytes = mu; // PRG size 
    uint8_t** cw = (uint8_t**) malloc(sizeof(uint8_t*)*p2);
    for (int i = 0; i < p2; i++) {
        cw[i] = (uint8_t*)malloc(mu);
        memcpy(cw[i],&key[nu*sigmaLength + i*mu],mu);
    }

    uint8_t* output = (uint8_t*)malloc(domainSize);
    memset(output,0,domainSize);

    for (int i = 0; i < nu; i++) {
        for (int j = 0; j < p2; j++) {
            if (s[i][j] != 0) {
                // XOR in G expansion and CW_i 
                unsigned char* tmp = (unsigned char*)malloc(mu);
                G(ctx, (uint8_t*)&s[i][j], mu,tmp);
                XOR(&output[i*mu],tmp,&output[i*mu],mu);
                XOR(&output[i*mu],cw[j],&output[i*mu],mu);
                free(tmp);
            }
        }
    }

    memcpy(*dataShare,output,domainSize);

    //free memory 
    for (int i = 0; i < nu; i++) {
        free(s[i]);
    }
    free(s);
    for (int i = 0; i < p2; i++) {
        free(cw[i]);
    }
    free(cw);
}

void evalAllOptMultiPartyDPF(EVP_CIPHER_CTX *ctx, int p, int log_domainSize, 
                        uint8_t* key, int t, uint8_t** dataShare) {
    int n = log_domainSize;
    int q = choose(p,t);
    int domainSize = pow(2, n);
    uint32_t p2 = (uint32_t)(pow(2, q-1));
    int mu_pow = ceil(log2(ceil((pow(2, n/2.0) * pow(2,(p-1)/2.0)))));
    uint64_t mu = (uint64_t)pow(2,mu_pow);
    uint64_t nu = (uint64_t)pow(2, n - mu_pow);

    int keyLength = calcMultiPartyOptDPFKeyLength(p,log_domainSize,t);
    int sigmaLength = 16*p2;

    // copy s and cw into arrays
    uint128_t** s = (uint128_t**) malloc(sizeof(uint128_t*) * nu);
    for (int i = 0; i < nu; i++) {
        s[i] = (uint128_t*) malloc(16*p2);
        for (int j = 0; j < p2; j++) {
            memcpy(&s[i][j], &key[i*sigmaLength + 16*j], 16);
        }
    }
    uint8_t** cw = (uint8_t**) malloc(sizeof(uint8_t*)*p2);
    for (int i = 0; i < p2; i++) {
        cw[i] = (uint8_t*)malloc(mu);
        memcpy(cw[i],&key[nu*sigmaLength + NUM_RSS_KEYS*nu*p2 + i*mu],mu);
    }

    uint8_t** output = (uint8_t**)malloc(NUM_RSS_KEYS*sizeof(uint8_t*));
    for (int i = 0; i < NUM_RSS_KEYS; i++) {
        output[i] = (uint8_t*)malloc(domainSize);
        memset(output[i],0,domainSize);
    }

    //[16*(p2*nu) + k*(nu*p2) + a*p2 + b]
    uint8_t*** toggleBits = (uint8_t***)malloc(NUM_RSS_KEYS*sizeof(uint8_t**));
    for (int i = 0; i < NUM_RSS_KEYS; i++) {
        toggleBits[i] = (uint8_t**)malloc(nu*sizeof(uint8_t*));
        for (int j = 0; j < nu; j++) {
            toggleBits[i][j] = (uint8_t*)malloc(p2);
        }
    }
    for (int i = 0; i < NUM_RSS_KEYS; i++) {
        for (int j = 0; j < nu; j++) {
            memcpy(toggleBits[i][j],&key[nu*sigmaLength + i*nu*p2 + j*p2],p2);
        }
    }

    uint8_t* tmp = (uint8_t*)malloc(mu); 
    for (int i = 0; i < nu; i++) {
        for (int j = 0; j < p2; j++) {
            G(ctx, (uint8_t*)&s[i][j], mu,tmp);
            for (int a = 0; a < NUM_RSS_KEYS; a++) {
                if (toggleBits[a][i][j] != 0) {
                    XOR(&output[a][i*mu],tmp,&output[a][i*mu],mu);
                    XOR(&output[a][i*mu],cw[j],&output[a][i*mu],mu);
                }
            }
        }
    }
    free(tmp);
    for (int i = 0; i < NUM_RSS_KEYS; i++) {
        memcpy(dataShare[i],output[i],domainSize);
    }
    //free memory 
    for (int i = 0; i < nu; i++) {
        free(s[i]);
    }
    free(s);
    for (int i = 0; i < p2; i++) {
        free(cw[i]);
    }
    free(cw);
}   

void evalAllOptMultiPartyDPFThread(EVP_CIPHER_CTX *ctx, int p, int log_domainSize, 
                        uint8_t* key, int t, uint8_t** dataShare, int threadIndex, int numThreads) {
    int n = log_domainSize;
    int q = choose(p,t);
    int domainSize = pow(2, n);
    uint32_t p2 = (uint32_t)(pow(2, q-1));
    int mu_pow = ceil(log2(ceil((pow(2, n/2.0) * pow(2,(p-1)/2.0)))));
    uint64_t mu = (uint64_t)pow(2,mu_pow);
    uint64_t nu = (uint64_t)pow(2, n - mu_pow);
    int slice = nu / numThreads;

    int keyLength = calcMultiPartyOptDPFKeyLength(p,log_domainSize,t);
    int sigmaLength = 16*p2;

    // copy s and cw into arrays
    uint128_t** s = (uint128_t**) malloc(sizeof(uint128_t*) * nu);
    for (int i = 0; i < nu; i++) {
        s[i] = (uint128_t*) malloc(16*p2);
        for (int j = 0; j < p2; j++) {
            memcpy(&s[i][j], &key[i*sigmaLength + 16*j], 16);
        }
    }

    uint8_t** cw = (uint8_t**) malloc(sizeof(uint8_t*)*p2);
    for (int i = 0; i < p2; i++) {
        cw[i] = (uint8_t*)malloc(mu);
        memcpy(cw[i],&key[nu*sigmaLength + NUM_RSS_KEYS*nu*p2 + i*mu],mu);
    }

    uint8_t** output = (uint8_t**)malloc(NUM_RSS_KEYS*sizeof(uint8_t*));
    for (int i = 0; i < NUM_RSS_KEYS; i++) {
        output[i] = (uint8_t*)malloc(domainSize);
        memset(output[i],0,domainSize);
    }

    uint8_t*** toggleBits = (uint8_t***)malloc(NUM_RSS_KEYS*sizeof(uint8_t**));
    for (int i = 0; i < NUM_RSS_KEYS; i++) {
        toggleBits[i] = (uint8_t**)malloc(nu*sizeof(uint8_t*));
        for (int j = 0; j < nu; j++) {
            toggleBits[i][j] = (uint8_t*)malloc(p2);
        }
    }
    for (int i = 0; i < NUM_RSS_KEYS; i++) {
        for (int j = 0; j < nu; j++) {
            memcpy(toggleBits[i][j],&key[nu*sigmaLength + i*nu*p2 + j*p2],p2);
        }
    }

    uint8_t* tmp = (uint8_t*)malloc(mu); 
    for (int i =  threadIndex*slice ; i < (threadIndex + 1)*slice; i++) {

        for (int j = 0; j < p2; j++) {
            G(ctx, (uint8_t*)&s[i][j], mu,tmp);
            for (int a = 0; a < NUM_RSS_KEYS; a++) {
                if (toggleBits[a][i][j] != 0) {
                    XOR(&output[a][i*mu],tmp,&output[a][i*mu],mu);
                    XOR(&output[a][i*mu],cw[j],&output[a][i*mu],mu);
                }
            }
        }
    }
    free(tmp);
    for (int i = 0; i < NUM_RSS_KEYS; i++) {
        memcpy(dataShare[i],output[i],domainSize);
    }
    //free memory 
    for (int i = 0; i < nu; i++) {
        free(s[i]);
    }
    free(s);
    for (int i = 0; i < p2; i++) {
        free(cw[i]);
    }
    free(cw);
}   

void evalAllCDThread(EVP_CIPHER_CTX *ctx, int p, int log_domainSize, 
                        uint8_t* key, int t, uint8_t** dataShare, int threadIndex, int numThreads) {
    int n = log_domainSize;
    int q = NUM_CD_KEYS_NEEDED;
    int domainSize = pow(2, n);
    uint32_t p2 = (uint32_t)(pow(2, q-1));
    int mu_pow = ceil((double)(n/2)) + 3;
    uint64_t mu = (uint64_t)pow(2,mu_pow);
    uint64_t nu = (uint64_t)pow(2, n - mu_pow);
    int slice = nu / numThreads;

    int keyLength = calcCDDPFKeyLength(p,log_domainSize,t,NUM_CD_KEYS_NEEDED,NUM_CD_KEYS);
    int sigmaLength = 16*p2;

    // copy s and cw into arrays
    uint128_t** s = (uint128_t**) malloc(sizeof(uint128_t*) * nu);
    for (int i = 0; i < nu; i++) {
        s[i] = (uint128_t*) malloc(16*p2);
        for (int j = 0; j < p2; j++) {
            memcpy(&s[i][j], &key[i*sigmaLength + 16*j], 16);
        }
    }
    uint8_t** cw = (uint8_t**) malloc(sizeof(uint8_t*)*p2);
    for (int i = 0; i < p2; i++) {
        cw[i] = (uint8_t*)malloc(mu);
        memcpy(cw[i],&key[nu*sigmaLength + NUM_CD_KEYS*nu*p2 + i*mu],mu);
    }

    uint8_t** output = (uint8_t**)malloc(NUM_CD_KEYS*sizeof(uint8_t*));
    for (int i = 0; i < NUM_CD_KEYS; i++) {
        output[i] = (uint8_t*)malloc(domainSize);
        memset(output[i],0,domainSize);
    }

    //[16*(p2*nu) + k*(nu*p2) + a*p2 + b]
    uint8_t*** toggleBits = (uint8_t***)malloc(NUM_CD_KEYS*sizeof(uint8_t**));
    for (int i = 0; i < NUM_CD_KEYS; i++) {
        toggleBits[i] = (uint8_t**)malloc(nu*sizeof(uint8_t*));
        for (int j = 0; j < nu; j++) {
            toggleBits[i][j] = (uint8_t*)malloc(p2);
        }
    }
    for (int i = 0; i < NUM_CD_KEYS; i++) {
        for (int j = 0; j < nu; j++) {
            memcpy(toggleBits[i][j],&key[nu*sigmaLength + i*nu*p2 + j*p2],p2);
        }
    }
    uint8_t* tmp = (uint8_t*)malloc(mu); 
    for (int i =  threadIndex*slice ; i < (threadIndex + 1)*slice; i++) {
        for (int j = 0; j < p2; j++) {
            G(ctx, (uint8_t*)&s[i][j], mu,tmp);
            for (int a = 0; a < NUM_CD_KEYS; a++) {
                if (toggleBits[a][i][j] != 0) {
                    XOR(&output[a][i*mu],tmp,&output[a][i*mu],mu);
                    XOR(&output[a][i*mu],cw[j],&output[a][i*mu],mu);
                }
            }
        }
    }
    free(tmp);
    for (int i = 0; i < NUM_CD_KEYS; i++) {
        memcpy(dataShare[i],output[i],domainSize);
    }

    //free memory 
    for (int i = 0; i < nu; i++) {
        free(s[i]);
    }
    free(s);

    for (int i = 0; i < p2; i++) {
        free(cw[i]);
    }
    free(cw);
}   