#include <iostream>
#include <cassert>
#include <cstring>
#include <math.h>     
#include "utils.h"
#include "coding.h"
#include "params.h"

void genWoodruffVs(int t, int m, uint8_t** v){
    for (int i = 0; i < t; i++) {
        memset(v[i],i,m);
    }
}

void genWoodruffQuery(uint128_t index, int t, int p, int m, uint8_t** v, uint8_t** key_output) {
    uint8_t* E_i = (uint8_t*)malloc(WOODRUFF_M);

    memset(E_i,0,WOODRUFF_M);
    for (int j = 0; j < WOODRUFF_D; j++) {
        E_i[MAPPING_INDEX[index][j]-1] = 1;
    }

    for (int i = 0; i < p; i++) {
        for (int j = 0; j < m; j++) {
            key_output[i][j] = E_i[j];
            for (int k = 0; k < t; k++) {
                key_output[i][j] ^= gf_mul(gf_pow(i+1,k+1),v[k][j]);
            }
        }
    }
}
