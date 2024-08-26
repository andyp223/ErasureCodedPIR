#include <iostream>
#include <cassert>
#include <cstring>
#include <math.h>     
#include "utils.h"
#include "coding.h"
#include "shamir_dpf.h"

// evaluation of polynomial at xval using Horner's method
void evalPoly(uint8_t* coeffs, int degree, int xval, uint8_t* output) {
    uint8_t tmp = coeffs[degree];
    for (int i = degree; i > 0; i--) {
        tmp = gf_mul(tmp,xval) ^ coeffs[i- 1]; 
    }

    memcpy(output, &tmp, 1);
}
// t = security threshold - withstand t corruptions aka degree t polynomial 
void genShamirDPF(int log_domainSize, uint128_t index, uint8_t b, int dataSize, int t, int p, uint8_t*** key_output) {
    int n = log_domainSize;

    uint8_t coeffs[2*n][t+1]; // coeffs of the random functions from constant to degree t term

    for (int i = 1; i <= n; i++) {
        int indexBit = getbit(index, log_domainSize, i);
        int KEEP, LOSE;
        if(indexBit == 0){
            coeffs[2*(i-1)][0] = (i == n) ? b : 1;
            coeffs[2*(i-1) + 1][0] = 0;
        }else{
            coeffs[2*(i-1)][0] = 0;
            coeffs[2*(i-1) + 1][0] = (i == n) ? b : 1;
        }
    }

    //Fill randomness in other spots 
    for (int i = 0; i < 2*n; i++) {
        gen_rand_bytes(&coeffs[i][1],t);
    }

    int keyLength = 2*n;
    uint8_t* buff[p];

    for (int j = 0; j < p; j++) {
        buff[j] = (uint8_t*) malloc(keyLength);
        for (int k = 0; k < 2*n; k++) {
            evalPoly(coeffs[k], t, j + 1, &buff[j][k]);
        }
    }

    for (int i = 0 ; i < p; i++) {
        memcpy((*key_output)[i],buff[i],keyLength);
        free(buff[i]);
    }
}

void genShamirCoeffs(int n, int t, int numRounds, uint128_t index, uint8_t*** coeffs_x, uint8_t*** coeffs_y) {
    int x = n/2 + (n % 2 != 0);
    int y = n - x;
    int xpow = get2pow(x);
    int ypow = get2pow(y);

    uint32_t gamma = index & ((1 << (n/2)) - 1); 
    uint32_t delta = (index & (((1 << (n+1)/2) - 1) << n/2)) >> n/2;
    uint8_t** randNumsX = (uint8_t**)malloc(numRounds*sizeof(uint8_t*));
    for (int i = 0 ; i < numRounds; i++) {
        randNumsX[i] = (uint8_t*)malloc(xpow*t);
        gen_rand_bytes(randNumsX[i],xpow*t);
    }
    uint8_t** randNumsY = (uint8_t**)malloc(numRounds*sizeof(uint8_t*));
    for (int i = 0 ; i < numRounds; i++) {
        randNumsY[i] = (uint8_t*)malloc(ypow*t);
        gen_rand_bytes(randNumsY[i],ypow*t);
    }

    for (int i = 0; i < numRounds; i++) {
        for (int j = 0; j < xpow; j++) {
            coeffs_x[i][j][t+i] = (j == delta) ? 1 : 0;
            //memcpy(&coeffs_x[i][j][0],&randNumsX[i][j*t],t);
        }
        for (int j = 0; j < ypow; j++) {
            coeffs_y[i][j][t+i] = (j == gamma) ? 1 : 0;
            //memcpy(&coeffs_y[i][j][0],&randNumsY[i][j*t],t);
        }
    }

    for (int i = 0 ; i < numRounds; i++) {
        free(randNumsX[i]);
        free(randNumsY[i]);
    }
    free(randNumsX);
    free(randNumsY);
}

void genOptShamirDPF(int log_domainSize, uint128_t index, int t, int p, int numRounds, uint8_t*** key_output, uint8_t*** coeffs_x, uint8_t*** coeffs_y) {
    int n = log_domainSize;
    int x = log_domainSize/2 + (log_domainSize % 2 != 0);
    int y = n - x;
    uint32_t gamma = index & ((1 << (n/2)) - 1); 
    uint32_t delta = (index & (((1 << (n+1)/2) - 1) << n/2)) >> n/2;

    int keyLength = calcShamirDPFKeyLength(n);

    uint8_t** buff[p];
    for (int i = 0; i < p; i++) {
        buff[i] = (uint8_t**)malloc(numRounds * sizeof(uint8_t*));
        for (int j = 0; j < numRounds; j++) {
            buff[i][j] = (uint8_t*)malloc(keyLength);
        }
    }

    for (int i = 0; i < p; i++) {
        for (int j = 0; j < numRounds; j++) {
            for (int k = 0; k < (int)pow(2,x); k++) {
                //printBuffer(coeffs_x[j][k],t+numRounds);
                evalPoly(coeffs_x[j][k],t+numRounds,i+1,&key_output[i][j][k]);
            } 
            for (int k = 0; k < (int)pow(2,y); k++) {
                evalPoly(coeffs_y[j][k],t+numRounds,i+1,&key_output[i][j][(int)pow(2,x) + k]);
            } 
        }
    }
}

void evalShamirDPF(int p, int party_index, int log_domainSize, uint8_t* key, uint128_t index, int dataSize, uint8_t* result) {
    int n = log_domainSize;
    uint8_t output = 1;
    for (int i = 1; i <= n; i++) {
        int indexBit = getbit(index, log_domainSize, i);
        output = gf_mul(output, key[2*(i - 1) + indexBit]);
    }
    memcpy(result,&output,1);
}

void evalAllShamirDPF(int p, int party_index, int log_domainSize, uint8_t* key, int dataSize, uint8_t** output) {
    int numLeaves = pow(2,log_domainSize);

    int n = log_domainSize;

    int currLevel = 0; 
    int levelIndex = 0; 
    int numIndexesInLevel = 2; 

    int treeSize = 2 * numLeaves - 1;

    uint8_t* tree_outputs = (uint8_t*)malloc(treeSize);
    tree_outputs[0] = 1;

    for (int i = 1; i < treeSize; i += 2) {
        int parentIndex = 0; 
        if (i > 1) {
            parentIndex = i - levelIndex - ((numIndexesInLevel - levelIndex) / 2);
        }

        int lIndex = i;
        int rIndex = i+1; 

        tree_outputs[lIndex] = gf_mul(tree_outputs[parentIndex], key[2*(currLevel)]);
        tree_outputs[rIndex] = gf_mul(tree_outputs[parentIndex], key[2*(currLevel) + 1]);

        levelIndex += 2;
        if (levelIndex == numIndexesInLevel) {
            currLevel++;
            numIndexesInLevel *= 2;
            levelIndex = 0;
        }
    }
    uint8_t* output_buff = (uint8_t*)malloc(numLeaves);
    memcpy(output_buff,&tree_outputs[treeSize - numLeaves],numLeaves);

    *output = output_buff;
}

void evalAllOptShamirDPF(int party_index, int log_domainSize, uint8_t** key, int numRounds, uint8_t** output) {
    int n = log_domainSize;
    int x = log_domainSize/2 + (log_domainSize % 2 != 0);
    int y = n - x;
    for (int i = 0; i < numRounds; i++) {
        for (int j = 0; j < (int)pow(2,n); j++) {
            uint32_t gamma = j & ((1 << (n/2)) - 1);
            uint32_t delta = (j & (((1 << (n+1)/2) - 1) << n/2)) >> n/2;
            //printf("%d %d\n", gamma, delta);

            output[i][j] = gf_mul(key[i][gamma], key[i][(int)pow(2,x) + delta]); 
        }

    }
}

void genHollantiDPF(int log_domainSize, uint128_t index, int t, int p, int numRounds, int rho, uint8_t*** key_output) {
    int n = log_domainSize;
    int domainSize = (int)pow(2, log_domainSize);

    uint8_t*** coeffs = (uint8_t***)malloc(numRounds*sizeof(uint8_t**));
    for (int i = 0; i < numRounds; i++) {
        coeffs[i] = (uint8_t**)malloc(domainSize*sizeof(uint8_t*));
        for (int j = 0; j < domainSize; j++) {
            coeffs[i][j] = (uint8_t*)malloc(t+(rho*numRounds));
            memset(coeffs[i][j],0,t+(rho*numRounds));
        }
    } 

    uint8_t** randNums = (uint8_t**)malloc(numRounds*sizeof(uint8_t*));
    for (int i = 0 ; i < numRounds; i++) {
        randNums[i] = (uint8_t*)malloc(domainSize*t);
        gen_rand_bytes(randNums[i],domainSize*t);
    }

    for (int i = 0; i < numRounds; i++) {
        for (int j = 0; j < domainSize; j++) {
            //printf("%d\n", coeffs[i][j][0]);
            memcpy(coeffs[i][j],&randNums[i][j*t],t);
            coeffs[i][j][t+((i+1)*rho) - 1] = (j == index) ? 1 : 0;
        }
    }

    uint8_t** buff[p];
    for (int i = 0; i < p; i++) {
        buff[i] = (uint8_t**)malloc(numRounds * sizeof(uint8_t*));
        for (int j = 0; j < numRounds; j++) {
            buff[i][j] = (uint8_t*)malloc(domainSize);
        }
    }

    for (int i = 0; i < p; i++) {
        for (int j = 0; j < numRounds; j++) {
            for (int k = 0; k < domainSize; k++) {
                evalPoly(coeffs[j][k],t+(rho*numRounds),i+1,&key_output[i][j][k]);
            } 
        }
    }

    for (int i = 0 ; i < numRounds; i++) {
        free(randNums[i]);
    }
    free(randNums);

}