#include <iostream>
#include <cassert>
#include <cstring>
#include <math.h>     
#include "utils.h"
#include "dpf_tree.h"
#include "coding.h"

typedef unsigned __int128 uint128_t;
void genDPF(EVP_CIPHER_CTX *ctx, int log_domainSize, uint128_t index, int dataSize, 
                        std::vector<uint8_t> finalCW_values, int p, uint8_t*** key_output) {
    assert(finalCW_values.size() == p - 1);

    uint32_t prg_output_len = blen(p);
    int maxLayer = log_domainSize;

    uint128_t s[maxLayer + 1][p];
    // Generate initial seeds
    for (int i = 0; i < p; i ++) { 
        gen_rand_key((uint8_t*)&s[0][i]);
    }

    // Initialize control bits
    int t[maxLayer + 1][p][p-1]; 
    for (int i = 0; i < p; i ++) {
        for (int j = 1; j < p; j++) {
            if (i == j) {
                t[0][i][j-1] = 1;
            }else {
                t[0][i][j-1] = 0;
            }
        }
    } 
    uint128_t s_tmp[p][2]; // 0 = L , 1 = R
    int t_tmp[p][2*p - 2]; // first p-1 is L, second p-1 is R
    int CWk_len = (2*p - 2 + 16);
    int CW_len = (p-1) * (2*p - 2 + 16);
    uint8_t CWs[maxLayer][p-1][CWk_len];
    // Start loop for each index bit 
    for (int i = 1; i <= maxLayer; i++) {
        // PRG and parse 
        for (int j = 0; j < p; j++) {
            unsigned char* tmp = (unsigned char*)malloc(prg_output_len);
            G(ctx, (uint8_t*)&s[i-1][j],prg_output_len,tmp);
            parse_prg_output(tmp, (uint8_t*)&s_tmp[j][0], (uint8_t*)&s_tmp[j][1], &t_tmp[j][0], p);
            free(tmp);
        }
        int KEEP, LOSE;
        int indexBit = getbit(index, log_domainSize, i);
        if(indexBit == 0){
            KEEP = 0;
            LOSE = 1;
        }else{
            KEEP = 1;
            LOSE = 0;
        }
        uint128_t sCW_k[p-1];
        int tCW_k[p-1][2*p-2]; // first indexes the CW number, second indexes the bit
        for (int j = 0; j < p-1; j++) {
            XOR((uint8_t*)&s_tmp[0][LOSE],(uint8_t*)&s_tmp[j+1][LOSE],(uint8_t*)&sCW_k[j],16);
        }
        for (int j = 0; j < p-1; j ++) {
            for (int m = 0; m < p-1; m++) {
                if (j == m) {
                    tCW_k[j][m] = t_tmp[0][m] ^ t_tmp[j+1][m] ^ indexBit ^ 1;
                    tCW_k[j][p - 1 + m] = t_tmp[0][p - 1 + m] ^ t_tmp[j+1][p - 1 + m] ^ indexBit;
                }else {
                    tCW_k[j][m] = t_tmp[0][m] ^ t_tmp[j+1][m];
                    tCW_k[j][p - 1 + m] = t_tmp[0][p - 1 + m] ^ t_tmp[j+1][p - 1 + m];
                }
            }
        }

        for (int j = 0; j < p - 1; j++) {
            uint8_t *tmp = (uint8_t *)&sCW_k[j];
            for (int k = 0; k < 16; k++) {
                CWs[i - 1][j][k] = tmp[k];
            }
            for (int k = 0; k < 2*p - 2; k++) {
                CWs[i - 1][j][16 + k] = tCW_k[j][k];
            }
        }
        
        // Set next seed value 
        for(int b = 0; b < p; b++) {
            s[i][b] = s_tmp[b][KEEP];
            for(int k = 0; k < p - 1; k++) {
                if (t[i-1][b][k] == 1) {
                    XOR((uint8_t*)&s[i][b],(uint8_t*)&sCW_k[k],(uint8_t*)&s[i][b],16);
                }
            }
        }

        // Set next t value
        for(int b = 0; b < p; b++) {
            for(int k = 0; k < p - 1; k++) {
                t[i][b][k] = t_tmp[b][KEEP*(p-1) + k];
                for (int m = 0; m < p - 1; m++) {
                    if (t[i-1][b][m] == 1) {
                        t[i][b][k] = t[i][b][k] ^ tCW_k[m][KEEP*(p-1) + k];
                    }
                }
            }
        }
    }

    // Set final CW 
    uint8_t convert[p];
    for (int j = 0; j < p; j++) {
        unsigned char* tmp = (unsigned char*)malloc(16);
        G(ctx, (uint8_t*)&s[maxLayer][j],16,tmp);
        memcpy(&convert[j], tmp, 1);
        free(tmp);
    }

    uint8_t lastCW[p-1];
    for (int j = 1; j < p; j++) {
        lastCW[j-1] = finalCW_values[j-1] ^ convert[0] ^ convert[j];
    }

    //Correction word for seed level 
    int keyLength = 16 + (maxLayer * CW_len) + p - 1;
    uint8_t* buff[p];
    for (int j = 0; j < p; j++) {
        buff[j] = (uint8_t*) malloc(keyLength);
        memcpy(&buff[j][0],&s[0][j],16);
        for (int k = 0; k < maxLayer; k++) {
            for (int kk = 0; kk < p - 1; kk++){
                memcpy(&buff[j][16 + k*CW_len + kk*CWk_len], &CWs[k][kk][0],CWk_len);
            }
        }
        for (int k = 0; k < p - 1; k++) {
            memcpy(&buff[j][16 + (maxLayer * CW_len) + k], &lastCW[k],1);
        }
    }
    for (int i = 0 ; i < p; i++) {
        memcpy((*key_output)[i],buff[i],keyLength);
        free(buff[i]);
    }
}

void genOptimizedDPF(EVP_CIPHER_CTX *ctx, int log_domainSize, uint128_t index, int dataSize, 
                        std::vector<uint8_t> finalCW_values, int p, int numQueries, uint8_t*** key_output) {
    assert(finalCW_values.size() == numQueries*(p - 1));
    uint32_t prg_output_len = blen(p);
    int maxLayer = log_domainSize;

    uint128_t s[maxLayer + 1][p];
    // Generate initial seeds
    for (int i = 0; i < p; i ++) { 
        gen_rand_key((uint8_t*)&s[0][i]);
    }

    // Initialize control bits
    int t[maxLayer + 1][p][p-1]; 
    for (int i = 0; i < p; i ++) {
        for (int j = 1; j < p; j++) {
            if (i == j) {
                t[0][i][j-1] = 1;
            }else {
                t[0][i][j-1] = 0;
            }
        }
    } 
    uint128_t s_tmp[p][2]; // 0 = L , 1 = R
    int t_tmp[p][2*p - 2]; // first p-1 is L, second p-1 is R
    int CWk_len = (2*p - 2 + 16);
    int CW_len = (p-1) * (2*p - 2 + 16);
    uint8_t CWs[maxLayer][p-1][CWk_len];
    // Start loop for each index bit 
    for (int i = 1; i <= maxLayer; i++) {
        // PRG and parse 
        for (int j = 0; j < p; j++) {
            unsigned char* tmp = (unsigned char*)malloc(prg_output_len);
            G(ctx, (uint8_t*)&s[i-1][j],prg_output_len,tmp);
            parse_prg_output(tmp, (uint8_t*)&s_tmp[j][0], (uint8_t*)&s_tmp[j][1], &t_tmp[j][0], p);
            free(tmp);
        }
        int KEEP, LOSE;
        int indexBit = getbit(index, log_domainSize, i);
        if(indexBit == 0){
            KEEP = 0;
            LOSE = 1;
        }else{
            KEEP = 1;
            LOSE = 0;
        }
        uint128_t sCW_k[p-1];
        int tCW_k[p-1][2*p-2]; // first indexes the CW number, second indexes the bit
        for (int j = 0; j < p-1; j++) {
            XOR((uint8_t*)&s_tmp[0][LOSE],(uint8_t*)&s_tmp[j+1][LOSE],(uint8_t*)&sCW_k[j],16);
        }
        for (int j = 0; j < p-1; j ++) {
            for (int m = 0; m < p-1; m++) {
                if (j == m) {
                    tCW_k[j][m] = t_tmp[0][m] ^ t_tmp[j+1][m] ^ indexBit ^ 1;
                    tCW_k[j][p - 1 + m] = t_tmp[0][p - 1 + m] ^ t_tmp[j+1][p - 1 + m] ^ indexBit;
                }else {
                    tCW_k[j][m] = t_tmp[0][m] ^ t_tmp[j+1][m];
                    tCW_k[j][p - 1 + m] = t_tmp[0][p - 1 + m] ^ t_tmp[j+1][p - 1 + m];
                }
            }
        }

        for (int j = 0; j < p - 1; j++) {
            uint8_t *tmp = (uint8_t *)&sCW_k[j];
            for (int k = 0; k < 16; k++) {
                CWs[i - 1][j][k] = tmp[k];
            }
            for (int k = 0; k < 2*p - 2; k++) {
                CWs[i - 1][j][16 + k] = tCW_k[j][k];
            }
        }
        
        // Set next seed value 
        for(int b = 0; b < p; b++) {
            s[i][b] = s_tmp[b][KEEP];
            for(int k = 0; k < p - 1; k++) {
                if (t[i-1][b][k] == 1) {
                    XOR((uint8_t*)&s[i][b],(uint8_t*)&sCW_k[k],(uint8_t*)&s[i][b],16);
                }
            }
        }

        // Set next t value
        for(int b = 0; b < p; b++) {
            for(int k = 0; k < p - 1; k++) {
                t[i][b][k] = t_tmp[b][KEEP*(p-1) + k];
                for (int m = 0; m < p - 1; m++) {
                    if (t[i-1][b][m] == 1) {
                        t[i][b][k] = t[i][b][k] ^ tCW_k[m][KEEP*(p-1) + k];
                    }
                }
            }
        }
    }

    // Set final CW 
    uint8_t convert[p][numQueries];
    for (int j = 0; j < p; j++) {
        unsigned char* tmp = (unsigned char*)malloc(16);
        G(ctx, (uint8_t*)&s[maxLayer][j],16,tmp);
        memcpy(&convert[j], tmp, numQueries);
        free(tmp);
    }

    uint8_t lastCW[p-1][numQueries];
    for (int j = 1; j < p; j++) {
        for (int k = 0; k < numQueries; k++) {
            lastCW[j-1][k] = finalCW_values[k*(p-1) + j-1] ^ convert[0][k] ^ convert[j][k];
        }
    }

    int keyLength = 16 + (maxLayer * CW_len) + numQueries*(p - 1);
    uint8_t* buff[p];
    for (int j = 0; j < p; j++) {
        buff[j] = (uint8_t*) malloc(keyLength);
        memcpy(&buff[j][0],&s[0][j],16);
        for (int k = 0; k < maxLayer; k++) {
            for (int kk = 0; kk < p - 1; kk++){
                memcpy(&buff[j][16 + k*CW_len + kk*CWk_len], &CWs[k][kk][0],CWk_len);
            }
        }
        for (int k = 0; k < p - 1; k++) {
            for (int a = 0; a < numQueries; a++) {
                memcpy(&buff[j][16 + (maxLayer * CW_len) + a*(p - 1) + k], &lastCW[k][a],1);
            }
        }
    }
    for (int i = 0 ; i < p; i++) {
        memcpy((*key_output)[i],buff[i],keyLength);
        free(buff[i]);
    }
}

// DPF eval 
void evalDPF(EVP_CIPHER_CTX *ctx, int p, int party_index, int log_domainSize, 
                        uint8_t* key, uint128_t index, int dataSize, uint8_t* result) {

    int maxLayer = log_domainSize;
    int CWk_len = (2*p - 2 + 16);
    int CW_len = (p-1) * (2*p - 2 + 16);
    int keyLength = 16 + (maxLayer * CW_len) + p - 1;
    uint32_t prg_output_len = blen(p);

    uint128_t s[maxLayer + 1];
    int t[maxLayer + 1][p-1];
	uint128_t sCW[maxLayer][p-1];
	int tCW[maxLayer][p-1][2*p - 2];
    uint8_t lastCWs[p-1];

    for (int j = 1; j < p; j++) {
        if (j == party_index) {
            t[0][j-1] = 1;
        }else {
            t[0][j-1] = 0;
        }
    }

    // parse k 
    memcpy(&s[0],&key[0],16);

    for (int i = 0; i <maxLayer; i++) {
        for (int j = 0; j < p - 1; j++) {
            memcpy(&sCW[i][j],&key[16 + i*CW_len + j*CWk_len],16);
            for (int k = 0; k < 2*p - 2; k++) {
                tCW[i][j][k] = key[16 + i*CW_len + j*CWk_len + 16 + k];
            }
        }
    }
    for (int i = 0; i < p - 1; i++) {
        lastCWs[i] = key[16 + (maxLayer * CW_len) + i];
    }

    // evaluation 
    uint128_t s_tmp[2]; // 0 = L , 1 = R
    int t_tmp[2*p - 2]; // first p-1 is L, second p-1 is R
    for (int i = 1; i <= maxLayer; i++) {
        unsigned char* tmp = (unsigned char*)malloc(16*prg_output_len);
        G(ctx, (uint8_t*)&s[i-1],16*prg_output_len,tmp);
        parse_prg_output(tmp, (uint8_t*)&s_tmp[0], (uint8_t*)&s_tmp[1], &t_tmp[0], p);
        free(tmp);
        for (int j = 0; j < p-1; j++) {
            if (t[i-1][j] == 1) {
                XOR((uint8_t*)&s_tmp[0],(uint8_t*)&sCW[i-1][j],(uint8_t*)&s_tmp[0],16);
                XOR((uint8_t*)&s_tmp[1],(uint8_t*)&sCW[i-1][j],(uint8_t*)&s_tmp[1],16);
                for (int k = 0; k < 2*p - 2; k++) {
                    t_tmp[k] = t_tmp[k] ^ tCW[i-1][j][k];
                }
            }
        }

        int KEEP, LOSE;
        int indexBit = getbit(index, log_domainSize, i);
        if(indexBit == 0){
            KEEP = 0;
            LOSE = 1;
        }else{
            KEEP = 1;
            LOSE = 0;
        }
        s[i] = s_tmp[KEEP];
        for (int j = 0; j < p - 1; j ++) {
            t[i][j] = t_tmp[KEEP*(p - 1) + j];
        }
    }
    unsigned char* tmp = (unsigned char*)malloc(16);
    G(ctx, (uint8_t*)&s[maxLayer],16,tmp);
    uint8_t output = tmp[0];
    for (int i = 0; i < p-1; i++) {
        if (t[maxLayer][i] == 1) {
            output ^= lastCWs[i];
        }
    }
    memcpy(result,&output,1);
}

// DPF eval 
// party_index must be 0 indexed 
void evalAllDPF(EVP_CIPHER_CTX *ctx, int p, int party_index, int log_domainSize, 
                        uint8_t* key, int dataSize, uint8_t** dataShare) {
    int numLeaves = pow(2, log_domainSize);

    int maxLayer = log_domainSize;

    int currLevel = 0;
    int levelIndex = 0;
    int numIndexesInLevel = 2;

    int CWk_len = (2*p - 2 + 16);
    int CW_len = (p-1) * (2*p - 2 + 16);
    int keyLength = 16 + (maxLayer * CW_len) + p - 1;
    uint32_t prg_output_len = blen(p);
    int treeSize = 2 * numLeaves - 1;
    uint128_t* s = (uint128_t*)malloc(16*treeSize);

    int** t = (int **)malloc(treeSize * sizeof(int*));
    for (int i = 0; i < treeSize; i++) {
        t[i] = (int*)malloc(p - 1);
    }
	uint128_t sCW[maxLayer][p-1];
	int tCW[maxLayer][p-1][2*p - 2];
    uint8_t lastCWs[p-1];

    for (int j = 1; j < p; j++) {
        if (j == party_index) {
            t[0][j-1] = 1;
        }else {
            t[0][j-1] = 0;
        }
    }

    memcpy(&s[0],&key[0],16);

    for (int i = 0; i < maxLayer; i++) {
        for (int j = 0; j < p - 1; j++) {
            memcpy(&sCW[i][j],&key[16 + i*CW_len + j*CWk_len],16);
            for (int k = 0; k < 2*p - 2; k++) {
                tCW[i][j][k] = key[16 + i*CW_len + j*CWk_len + 16 + k];
            }
        }
    }

    for (int i = 0; i < p - 1; i++) {
        lastCWs[i] = key[16 + (maxLayer * CW_len) + i];
    }

    // evaluation 
    uint128_t s_tmp[2]; // 0 = L , 1 = R
    int t_tmp[2*p - 2]; // first p-1 is L, second p-1 is R
    for (int i = 1; i < treeSize; i+=2) {
        int parentIndex = 0; 
        if (i > 1) {
            parentIndex = i - levelIndex - ((numIndexesInLevel - levelIndex) / 2);
        }
        unsigned char* tmp = (unsigned char*)malloc(prg_output_len);
        G(ctx, (uint8_t*)&s[maxLayer],prg_output_len,tmp);
        parse_prg_output(tmp, (uint8_t*)&s_tmp[0], (uint8_t*)&s_tmp[1], &t_tmp[0], p);
        free(tmp);
        for (int j = 0; j < p-1; j++) {
            if (t[parentIndex][j] == 1) {
                XOR((uint8_t*)&s_tmp[0],(uint8_t*)&sCW[currLevel][j],(uint8_t*)&s_tmp[0],16);
                XOR((uint8_t*)&s_tmp[1],(uint8_t*)&sCW[currLevel][j],(uint8_t*)&s_tmp[1],16);
                for (int k = 0; k < 2*p - 2; k++) {
                    t_tmp[k] = t_tmp[k] ^ tCW[currLevel][j][k];
                }
            }
        }

        int lIndex = i; 
        int rIndex = i+1;

        s[lIndex] = s_tmp[0]; 
        s[rIndex] = s_tmp[1]; 
        for (int j = 0; j < p - 1; j ++) {
            t[lIndex][j] = t_tmp[j];
            t[rIndex][j] = t_tmp[(p - 1) + j];
        }

        levelIndex += 2;
        if (levelIndex == numIndexesInLevel) {
            currLevel++;
            numIndexesInLevel *= 2;
            levelIndex = 0;
        }
    }

    uint8_t* domain_eval;
    domain_eval = (uint8_t*) malloc(numLeaves);
    for (int j = 0; j < numLeaves; j++) {
        int index = treeSize - numLeaves + j; 
        unsigned char* tmp = (unsigned char*)malloc(16);
        G(ctx, (uint8_t*)&s[index],16,tmp);
        uint8_t tmp_output = tmp[0];
        free(tmp);
        for (int i = 0; i < p-1; i++) {
            if (t[index][i] == 1) {
                tmp_output ^= lastCWs[i];
            }
        }
        domain_eval[j] = tmp_output;
    }

    memcpy(*dataShare,domain_eval,numLeaves);
    free(s);
    for (int i = 0; i < treeSize; i ++) {
        free(t[i]);
    }
    free(t);
    free(domain_eval);
}

void evalAllOptimizedDPF(EVP_CIPHER_CTX *ctx, int p, int party_index, int log_domainSize, 
                        uint8_t* key, int dataSize, int numQueries, uint8_t** dataShare) {
    int numLeaves = pow(2, log_domainSize);
    int maxLayer = log_domainSize;
    int currLevel = 0;
    int levelIndex = 0;
    int numIndexesInLevel = 2;
    int CWk_len = (2*p - 2 + 16);
    int CW_len = (p-1) * (2*p - 2 + 16);
    int keyLength = 16 + (maxLayer * CW_len) + numQueries* (p - 1);
    uint32_t prg_output_len = blen(p);  
    int treeSize = 2 * numLeaves - 1;
    uint128_t* s = (uint128_t*)malloc(16*treeSize);

    int** t = (int **)malloc(treeSize * sizeof(int*));
    for (int i = 0; i < treeSize; i++) {
        t[i] = (int*)malloc(sizeof(int)*(p - 1));
    }
    
	uint128_t sCW[maxLayer][p-1];
	int tCW[maxLayer][p-1][2*p - 2];
    uint8_t lastCWs[p-1][numQueries];

    for (int j = 1; j < p; j++) {
        if (j == party_index) {
            t[0][j-1] = 1;
        }else {
            t[0][j-1] = 0;
        }
    }

    memcpy(&s[0],&key[0],16);
    
    for (int i = 0; i < maxLayer; i++) {
        for (int j = 0; j < p - 1; j++) {
            memcpy(&sCW[i][j],&key[16 + i*CW_len + j*CWk_len],16);
            for (int k = 0; k < 2*p - 2; k++) {
                tCW[i][j][k] = key[16 + i*CW_len + j*CWk_len + 16 + k];
            }
        }
    }
    
    for (int i = 0; i < p - 1; i++) {
        for (int j = 0; j < numQueries; j++) {
            lastCWs[i][j] = key[16 + (maxLayer * CW_len) + j*(p - 1) + i];
        }
    }

    // evaluation 
    uint128_t s_tmp[2]; // 0 = L , 1 = R
    int t_tmp[2*p - 2]; // first p-1 is L, second p-1 is R
    unsigned char* tmp = (unsigned char*)malloc(prg_output_len);
    for (int i = 1; i < treeSize; i+=2) {
        int parentIndex = 0; 
        if (i > 1) {
            parentIndex = i - levelIndex - ((numIndexesInLevel - levelIndex) / 2);
        }
        G(ctx, (uint8_t*)&s[parentIndex],prg_output_len,tmp);
        parse_prg_output(tmp, (uint8_t*)&s_tmp[0], (uint8_t*)&s_tmp[1], &t_tmp[0], p);

        for (int j = 0; j < p-1; j++) {
            if (t[parentIndex][j] == 1) {
                XOR((uint8_t*)&s_tmp[0],(uint8_t*)&sCW[currLevel][j],(uint8_t*)&s_tmp[0],16);
                XOR((uint8_t*)&s_tmp[1],(uint8_t*)&sCW[currLevel][j],(uint8_t*)&s_tmp[1],16);
                for (int k = 0; k < 2*p - 2; k++) {
                    t_tmp[k] = t_tmp[k] ^ tCW[currLevel][j][k];
                }
            }
        }

        int lIndex = i; 
        int rIndex = i+1;

        s[lIndex] = s_tmp[0]; 
        s[rIndex] = s_tmp[1]; 
        for (int j = 0; j < p - 1; j ++) {
            t[lIndex][j] = t_tmp[j];
            t[rIndex][j] = t_tmp[(p - 1) + j];
        }

        levelIndex += 2;
        if (levelIndex == numIndexesInLevel) {
            currLevel++;
            numIndexesInLevel *= 2;
            levelIndex = 0;
        }
    }
    free(tmp);

    uint8_t** domain_eval = (uint8_t**)malloc(numQueries*sizeof(uint8_t*));
    for (int i = 0; i < numQueries; i++) {
        domain_eval[i] = (uint8_t*) malloc(numLeaves);
    }

    unsigned char* tmpPRGOutput = (unsigned char*)malloc(16);
    for (int j = 0; j < numLeaves; j++) {
        int index = treeSize - numLeaves + j; 
        G(ctx, (uint8_t*)&s[index],16,tmpPRGOutput);
        for (int k = 0; k < numQueries; k++) {
            uint8_t tmp_output = tmpPRGOutput[k]; 
            for (int i = 0; i < p-1; i++) {
                if (t[index][i] == 1) {
                    tmp_output ^= lastCWs[i][k];
                }
            }
            domain_eval[k][j] = tmp_output;
        }
    }
    for (int i = 0; i < numQueries; i++) {
        memcpy((dataShare[i]),domain_eval[i],numLeaves);
    }

    free(tmpPRGOutput);
    free(s);
    
    for (int i = 0; i < treeSize; i ++) {
        free(t[i]);
    }
    free(t);
    for (int i = 0; i < numQueries; i++) {
        free(domain_eval[i]);
    }
    
    free(domain_eval);
    
}

void evalAllOptimizedDPFThread(EVP_CIPHER_CTX *ctx, int p, int party_index, int log_domainSize, 
                        uint8_t* key, int dataSize, int numQueries, uint8_t** dataShare, 
                        int threadNum, int numThreads) {
    int packed = 16 / numQueries; 
    int savedLayers = log2(packed); 
    int numThreadLayers = log2(numThreads); 
    int maxLayer = log_domainSize - numThreadLayers - savedLayers;
    int numLeaves = pow(2, log_domainSize - numThreadLayers - savedLayers);

    int currLevel = numThreadLayers;
    int levelIndex = 0;
    int numIndexesInLevel = 2;


    int CWk_len = (2*p - 2 + 16);
    int CW_len = (p-1) * (2*p - 2 + 16);
    uint32_t prg_output_len = blen(p);  

    int treeSize = 2 * numLeaves - 1;
    uint128_t* s = (uint128_t*)malloc(16*treeSize);

    int** t = (int **)malloc(treeSize * sizeof(int*));
    for (int i = 0; i < treeSize; i++) {
        t[i] = (int*)malloc(sizeof(int)*(p - 1));
    }
    
	uint128_t sCW[log_domainSize][p-1];
	int tCW[log_domainSize][p-1][2*p - 2];
    uint8_t lastCWs[p-1][numQueries];

    for (int j = 1; j < p; j++) {
        if (j == party_index) {
            t[0][j-1] = 1;
        }else {
            t[0][j-1] = 0;
        }
    }

    memcpy(&s[0],&key[0],16);
    
    for (int i = 0; i < log_domainSize; i++) {
        for (int j = 0; j < p - 1; j++) {
            memcpy(&sCW[i][j],&key[16 + i*CW_len + j*CWk_len],16);
            for (int k = 0; k < 2*p - 2; k++) {
                tCW[i][j][k] = key[16 + i*CW_len + j*CWk_len + 16 + k];
            }
        }
    }
    
    for (int i = 0; i < p - 1; i++) {
        for (int j = 0; j < numQueries; j++) {
            lastCWs[i][j] = key[16 + (log_domainSize * CW_len) + j*(p - 1) + i];
        }
    }
    // eval to thread root 
    uint128_t s_tmp[2]; // 0 = L , 1 = R
    int t_tmp[2*p - 2]; // first p-1 is L, second p-1 is R
    for (int i = 1; i <= numThreadLayers; i++) {
        unsigned char* prgtmp = (unsigned char*)malloc(prg_output_len);
        G(ctx, (uint8_t*)&s[0],prg_output_len,prgtmp);
        parse_prg_output(prgtmp, (uint8_t*)&s_tmp[0], (uint8_t*)&s_tmp[1], &t_tmp[0], p);
        for (int j = 0; j < p-1; j++) {
            if (t[0][j] == 1) {
                XOR((uint8_t*)&s_tmp[0],(uint8_t*)&sCW[i-1][j],(uint8_t*)&s_tmp[0],16);
                XOR((uint8_t*)&s_tmp[1],(uint8_t*)&sCW[i-1][j],(uint8_t*)&s_tmp[1],16);
                for (int k = 0; k < 2*p - 2; k++) {
                    t_tmp[k] = t_tmp[k] ^ tCW[i-1][j][k];
                }
            }
        }

        int KEEP, LOSE;
        int indexBit = getbit(threadNum, log2(numThreads), i);
        if(indexBit == 0){
            KEEP = 0;
            LOSE = 1;
        }else{
            KEEP = 1;
            LOSE = 0;
        }
        s[0] = s_tmp[KEEP];
        for (int j = 0; j < p - 1; j ++) {
            t[0][j] = t_tmp[KEEP*(p - 1) + j];
        }
    }
    // evaluation 
    unsigned char* tmp = (unsigned char*)malloc(prg_output_len);
    for (int i = 1; i < treeSize; i+=2) {
        int parentIndex = 0; 
        if (i > 1) {
            parentIndex = i - levelIndex - ((numIndexesInLevel - levelIndex) / 2);
        }
        G(ctx, (uint8_t*)&s[parentIndex],prg_output_len,tmp);
        parse_prg_output(tmp, (uint8_t*)&s_tmp[0], (uint8_t*)&s_tmp[1], &t_tmp[0], p);

        for (int j = 0; j < p-1; j++) {
            if (t[parentIndex][j] == 1) {
                XOR((uint8_t*)&s_tmp[0],(uint8_t*)&sCW[currLevel][j],(uint8_t*)&s_tmp[0],16);
                XOR((uint8_t*)&s_tmp[1],(uint8_t*)&sCW[currLevel][j],(uint8_t*)&s_tmp[1],16);
                for (int k = 0; k < 2*p - 2; k++) {
                    t_tmp[k] = t_tmp[k] ^ tCW[currLevel][j][k];
                }
            }
        }

        int lIndex = i; 
        int rIndex = i+1;

        s[lIndex] = s_tmp[0]; 
        s[rIndex] = s_tmp[1]; 
        for (int j = 0; j < p - 1; j ++) {
            t[lIndex][j] = t_tmp[j];
            t[rIndex][j] = t_tmp[(p - 1) + j];
        }

        levelIndex += 2;
        if (levelIndex == numIndexesInLevel) {
            currLevel++;
            numIndexesInLevel *= 2;
            levelIndex = 0;
        }
    }
    free(tmp);

    uint8_t** domain_eval = (uint8_t**)malloc(numQueries*sizeof(uint8_t*));
    for (int i = 0; i < numQueries; i++) {
        domain_eval[i] = (uint8_t*) malloc(pow(2,log_domainSize));
        memset(domain_eval[i],0,pow(2,log_domainSize));
    }

    int slice = pow(2,log_domainSize)/numThreads;
    unsigned char* tmpPRGOutput = (unsigned char*)malloc(16);

    for (int j = 0; j < numLeaves; j++) {
        int index = treeSize - numLeaves + j; // needs to expand to (16/numQueries worth of indices)
        G(ctx, (uint8_t*)&s[index],16,tmpPRGOutput);
        for (int a = 0; a < numQueries; a++) {
            for (int b = 0; b < packed; b++) {
                uint8_t tmp_output = tmpPRGOutput[a*numQueries + b];
                for (int i = 0; i < p-1; i++) {
                    if (t[index][i] == 1) {
                        tmp_output ^= lastCWs[i][a];
                    }
                }
                domain_eval[a][threadNum*slice + a*numQueries + b] = tmp_output;
            }
        }
    }
    for (int i = 0; i < numQueries; i++) {
        memcpy((dataShare[i]),domain_eval[i],pow(2,log_domainSize));
    }

    free(tmpPRGOutput);
    free(s);
    
    for (int i = 0; i < treeSize; i ++) {
       free(t[i]);
    }
    free(t);
    for (int i = 0; i < numQueries; i++) {
        free(domain_eval[i]);
    }
    
    free(domain_eval);
    
}