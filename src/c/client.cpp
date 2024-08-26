#// include <openssl/rand.h>
#include <string.h>
#include <math.h>
#include <assert.h>

#include "coding.h"
#include "utils.h"
#include "dpf_tree.h"
#include "shamir_dpf.h"
#include "multiparty_dpf.h"
#include "client.h"
#include "params.h"
#include "interpolation.h"

// initializeClient 
void initialize_client(client *c, uint8_t log_num_files, uint32_t file_size_bytes) {
    c->ctx = EVP_CIPHER_CTX_new();
    uint32_t num_files = pow(2,log_num_files);
    c->macKey = (uint8_t*)"1234567812345678";
    c->unencoded_files = (uint8_t**)malloc(num_files * sizeof(uint8_t *));
    for (int i = 0; i < num_files; i++) {
        c->unencoded_files[i] = (uint8_t*)malloc(FILE_SIZE_BYTES);
        memset(c->unencoded_files[i], i, PAYLOAD_SIZE_BYTES);
        if(i == 1){
            for(int j = 0; j<PAYLOAD_SIZE_BYTES;j++){
                c->unencoded_files[i][j] = (uint8_t)j;
            }
        }
        if (CHECK_MAC) {
            mac(c->macKey,&(c->unencoded_files[i][0]), PAYLOAD_SIZE_BYTES, &(c->unencoded_files[i][PAYLOAD_SIZE_BYTES]), MAC_SIZE_BYTES);
        }
    } 
}

void free_client(client *c) {
    EVP_CIPHER_CTX_free(c->ctx);
    for (int i = 0; i < NUM_FILES; i++) {
        free(c->unencoded_files[i]);
    }
    free(c->unencoded_files);
}

void generate_encoded_within_file(client* c, int party_index, int file_index, uint8_t* encoded_file) {
    uint8_t* encodeMat = (uint8_t*) malloc(NUM_PARTIES * K); 
    gen_encode_matrix(encodeMat,NUM_PARTIES,K);
    uint8_t* tmp_file = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES*K);
    memset(tmp_file,0,ENCODED_FILE_SIZE_BYTES*K);
    memcpy(tmp_file,c->unencoded_files[file_index],FILE_SIZE_BYTES);
    for (int i = 0; i < ENCODED_FILE_SIZE_BYTES; i++) {
        for (int j = 0; j < K; j++) {
            encoded_file[i] ^= gf_mul(tmp_file[j*ENCODED_FILE_SIZE_BYTES + i],encodeMat[j*NUM_PARTIES + party_index - 1]);
        }
    }
    free(encodeMat);
    free(tmp_file);
}
void generate_hermite_within_file(client*c, int party_index, int file_index, uint8_t* encoded_file) {
    uint8_t* encodeMat = (uint8_t*) malloc(NUM_PARTIES * K); 
    gen_encode_matrix(encodeMat,NUM_PARTIES,K);
    uint8_t* tmp_file = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES*K);
    memset(tmp_file,0,ENCODED_FILE_SIZE_BYTES*K);
    memcpy(tmp_file,c->unencoded_files[file_index],FILE_SIZE_BYTES);
    for (int i = 0; i < ENCODED_FILE_SIZE_BYTES; i++) {
        for (int j = 1; j < K; j++) {
            encoded_file[i] ^= gf_mul(j%2, gf_mul(tmp_file[j*ENCODED_FILE_SIZE_BYTES + i],encodeMat[(j - 1)*NUM_PARTIES + party_index - 1]));
        }
    }   
}

void generate_encoded_across_file(client* c, int party_index, int file_index, uint8_t* encoded_file) {
    uint8_t* encodeMat = (uint8_t*) malloc(NUM_PARTIES * K); 
    int encDBsize = ceil((double)NUM_FILES/K);
    
    gen_encode_matrix(encodeMat,NUM_PARTIES,K);
    uint8_t** tmp_files = (uint8_t**)malloc(K*sizeof(uint8_t*));
    for (int i = 0; i < K; i++) {
        tmp_files[i] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        if ((encDBsize*i + file_index) >= NUM_FILES) {
            memset(tmp_files[i],0,ENCODED_FILE_SIZE_BYTES);
        } else {
            memcpy(tmp_files[i],c->unencoded_files[encDBsize*i + file_index], ENCODED_FILE_SIZE_BYTES);
        }
    }

    for (int i = 0; i < (int)ENCODED_FILE_SIZE_BYTES; i++) {
        for (int j = 0; j < K; j++) {
            encoded_file[i] ^= gf_mul(tmp_files[j][i],encodeMat[j*NUM_PARTIES + party_index - 1]);
        }
    }
    free(encodeMat);
}

void encode_across_files_server(client* c, server* s) {
    for (int i = 0; i < NUM_ENCODED_FILES; i++) {
        generate_encoded_across_file(c, s->partyIndex, i, s->indexList[i]);
    }
}

void encode_within_files_server(client* c, server* s) {
    for (int i = 0; i < NUM_ENCODED_FILES; i++) {
        generate_encoded_within_file(c, s->partyIndex, i, s->indexList[i]);
    }
    if (IS_HERMITE) {
        for (int i = 0; i < NUM_ENCODED_FILES; i++) {
            generate_hermite_within_file(c, s->partyIndex, i, s->indexList[NUM_ENCODED_FILES + i]);
        }
    }
}

//Verifies that a given MAC is correct
int checkMac(client* c, uint8_t* finalResult, uint8_t* mac, int across) {
    uint8_t tmp_mac[64];
    int mac_size = (int)(sizeof(uint8_t));
    uint8_t iv[128];
    memset(iv,31,128);
    EVP_EncryptInit_ex(c->ctx, EVP_aes_128_ecb(),  NULL, c->macKey, iv);
    uint8_t padded[128];
    memset(padded,0,128);
    for(int i = 0; i<FILE_SIZE_BYTES;i++) {
         padded[0] = finalResult[i];
         EVP_EncryptUpdate(c->ctx, &tmp_mac[0],&mac_size,padded,128);
         if(mac[i] != tmp_mac[0]){
            return -1;
         }
    }
    return 0;
}

void generate_DPF_tree_query(client *c, int index, uint8_t*** keys) {
    assert(T == 1);
    for (int i = 1; i <= NUM_ROUNDS; i++) {
        std::vector<uint8_t> final_CW_values; 
        if (K != 1) {
            for (int j = 2; j <= NUM_PARTIES; j++) {
                final_CW_values.push_back(gf_pow(j,i) ^ 1);
            } 
        } else {
            final_CW_values.push_back(1);
        }
        genDPF(c->ctx, LOG_NUM_ENCODED_FILES, index, ENCODED_FILE_SIZE_BYTES, final_CW_values, NUM_PARTIES, &keys[i-1]);
    }
}

void generate_opt_DPF_tree_query(client *c, int index, uint8_t*** keys) {
    assert(T == 1);
    std::vector<uint8_t> final_CW_values; 
    for (int i = 1; i <= NUM_ROUNDS; i++) {
        for (int j = 2; j <= NUM_PARTIES; j++) {
            final_CW_values.push_back(gf_pow(j,RHO*i) ^ 1);
        } 
    }
    genOptimizedDPF(c->ctx, LOG_NUM_ENCODED_FILES, index, ENCODED_FILE_SIZE_BYTES, final_CW_values, NUM_PARTIES, NUM_ROUNDS, keys);
}

void generateMultiPartyDPFQuery(client *c, int index, uint8_t*** keys) {
    genOptMultiPartyDPF(c->ctx, LOG_NUM_ENCODED_FILES, index, 1, NUM_PARTIES, T, keys);
}

void generateCDQuery(client *c, int index, uint8_t*** keys) {
    genCDDPF(c->ctx, LOG_NUM_ENCODED_FILES, index, 1, NUM_PARTIES, T, keys);
}

void generateShamirDPFQuery(client *c, int index, uint8_t*** keys) {
    assert(T > 1);
    int n = LOG_NUM_ENCODED_FILES;
    int x = n/2 + (n % 2 != 0);
    int y = n - x;

    uint32_t gamma = index & ((1 << (n/2)) - 1);
    uint32_t delta = (index & (((1 << (n+1)/2) - 1) << n/2)) >> n/2;

    uint8_t*** coeffs_x = (uint8_t***)malloc(NUM_ROUNDS*sizeof(uint8_t**));
    uint8_t*** coeffs_y = (uint8_t***)malloc(NUM_ROUNDS*sizeof(uint8_t**));
    for (int i = 0; i < NUM_ROUNDS; i++) {
        coeffs_x[i] = (uint8_t**)malloc((int)pow(2,x));
        coeffs_y[i] = (uint8_t**)malloc((int)pow(2,x));
        for (int j = 0; j < (int)pow(2,x); j++) {
            coeffs_x[i][j] = (uint8_t*)malloc(T+NUM_ROUNDS);
            memset(coeffs_x[i][j],0,T+NUM_ROUNDS);
        }
        for (int j = 0; j < (int)pow(2,y); j++) {
            coeffs_y[i][j] = (uint8_t*)malloc(T+NUM_ROUNDS);
            memset(coeffs_y[i][j],0,T+NUM_ROUNDS);
        }
    } 

    for (int i = 0; i < NUM_ROUNDS; i++) {
        for (int j = 0; j < (int)pow(2,x); j++) {
            gen_rand_bytes(&coeffs_x[i][j][0],T);
            coeffs_x[i][j][T + i] = (j == delta) ? 1 : 0;
        }
        for (int j = 0; j < (int)pow(2,y); j++) {
            gen_rand_bytes(&coeffs_y[i][j][0],T);
            coeffs_y[i][j][T + i] = (j == gamma) ? 1 : 0;
        }
    }
    genOptShamirDPF(LOG_NUM_ENCODED_FILES, index, T, NUM_PARTIES, NUM_ROUNDS, keys, coeffs_x, coeffs_y);

}

void generateHollantiQuery(client *c, int index, uint8_t*** keys) {
    genHollantiDPF(LOG_NUM_ENCODED_FILES, index, T, NUM_PARTIES, NUM_ROUNDS, RHO, keys);
}

void generateWoodruffQuery(client *c, int index, uint8_t*** keys) {
    uint8_t* randNums = (uint8_t*)malloc(WOODRUFF_M*T);
    gen_rand_bytes(randNums,WOODRUFF_M*T);
    
}

void assembleDPFTreeQueryResponses(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output) {
    int numResponses = NUM_PARTIES - R;

    uint8_t* tmpOutput = (uint8_t*)malloc(K*ENCODED_FILE_SIZE_BYTES);

    memset(tmpOutput,0,K*ENCODED_FILE_SIZE_BYTES);

    uint8_t** shares = (uint8_t**)malloc(ENCODED_FILE_SIZE_BYTES* sizeof(uint8_t*));
    uint8_t* evalPoints = (uint8_t*)malloc(numResponses); 
    uint8_t* tmp = (uint8_t*)malloc(K + RHO);

    for (int i = 0; i < ENCODED_FILE_SIZE_BYTES; i++) {
        shares[i] = (uint8_t*)malloc(numResponses);
    }
    for (int i = 0; i < NUM_ROUNDS; i++) {
        int curr = 1;
        for (int j = 0; j < numResponses; j++) {
            while (erasureIndexList[curr - 1] == 0) {
                curr++;
            }
            evalPoints[j] = curr;
            for (int a = 0; a < ENCODED_FILE_SIZE_BYTES; a++) {
                shares[a][j] = responses[j][i][a];
                if (i > 0) {
                    for (int b = 0; b < i; b++) {
                        shares[a][j] ^= gf_mul(tmpOutput[(K - 1 - b)*ENCODED_FILE_SIZE_BYTES + a], gf_pow(curr, K + i - b));
                    }
                }            
            }
            curr++; 
        }

        // decoding 
        for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
            if (B > 0) {
                lagrangeInterpolationMalicious(evalPoints, numResponses, shares[j], K + RHO - 1, B, tmp);
            } else {
                lagrangeInterpolationSemihonest(evalPoints, numResponses, shares[j], K + RHO - 1, tmp);
            }
            for (int k = 0; k < RHO; k++) {
                tmpOutput[(K - 1 - i - k)*ENCODED_FILE_SIZE_BYTES + j] = tmp[K + RHO - 1 - k];
            }
        }
    }
    if (ENCODE_ACROSS) {
        memcpy(output, tmpOutput, FILE_SIZE_BYTES);
    } else {
        memcpy(output, tmpOutput, FILE_SIZE_BYTES);
    }
    
    // free memory
    free(tmpOutput);
    for (int i = 0; i < ENCODED_FILE_SIZE_BYTES; i++) {
        free(shares[i]);
    }
    free(shares);
    free(tmp);
}

// assembleQueryResponses
// responses of the form numResponses x numRounds x encryptedFileSize
void assembleDPFTreeQueryResponsesSemiHonest(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output) {
    assembleDPFTreeQueryResponses(c,erasureIndexList,responses,output);
}

void assembleDPFTreeQueryResponsesMalicious(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output) {
    assembleDPFTreeQueryResponses(c,erasureIndexList,responses,output);
}

void assembleMultiPartyResponses(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output) {
    int q = choose(NUM_PARTIES,T);
    int numResponses = NUM_PARTIES - R;

    uint8_t** shares = (uint8_t**)malloc(FILE_SIZE_BYTES* sizeof(uint8_t*));

    for (int i = 0; i < FILE_SIZE_BYTES; i++) {
        shares[i] = (uint8_t*)malloc(K + 2*B);
    }

    uint8_t* tmpOutput = (uint8_t*)malloc(FILE_SIZE_BYTES);
    uint8_t* responsesIndexList = (uint8_t*)malloc(NUM_PARTIES);
    uint8_t* evalPoints = (uint8_t*)malloc(K + 2*B);

    int t = 0;
    for (int i = 0; i < NUM_PARTIES; i++) {
        if (erasureIndexList[i] == 1) {
            responsesIndexList[i] = t;
            t++;
        } else {
            responsesIndexList[i] = 255;
        }
    }

    uint8_t* tmp = (uint8_t*)malloc(K);
    for (int i = 0; i < q; i++) {
        memset(evalPoints,0,K + 2*B);

        int curr = 0; 
        int j = 0;
        while (curr < K + 2*B) {
            assert(j < NUM_PARTIES);

            if (PARTY_TO_POSITION_MAPPING[j][i] != 255 && erasureIndexList[j] == 1) {
                for (int a = 0; a < FILE_SIZE_BYTES; a++) {
                    shares[a][curr] = responses[responsesIndexList[j]][PARTY_TO_POSITION_MAPPING[j][i]][a];
                }
                evalPoints[curr] = j + 1;
                curr++;
            }
            j++;
        }
        for (int j = 0; j < FILE_SIZE_BYTES; j++) {
            if (B > 0) {
                lagrangeInterpolationMalicious(evalPoints, K + 2*B, shares[j], K - 1, B, tmp);
            } else {
                lagrangeInterpolationSemihonest(evalPoints, K, shares[j], K - 1, tmp);
            }
            tmpOutput[j] = tmp[0];
        }

        XOR(output, tmpOutput, output, FILE_SIZE_BYTES);
    }
    free(tmp);
}

void assembleMultiPartyResponsesSemiHonest(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output) {
    assembleMultiPartyResponses(c,erasureIndexList,responses,output);
}

void assembleMultiPartyResponsesMalicious(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output) {
    int q = choose(NUM_PARTIES,T);
    int numResponses = NUM_PARTIES - R;
    uint8_t* vandermondeMat = (uint8_t*)malloc(K*NUM_PARTIES);
    gen_encode_matrix(vandermondeMat, NUM_PARTIES, K);

    uint8_t** shares = (uint8_t**)malloc(FILE_SIZE_BYTES* sizeof(uint8_t*));

    for (int i = 0; i < FILE_SIZE_BYTES; i++) {
        shares[i] = (uint8_t*)malloc(K + 2*B);
    }

    uint8_t* decodeMat = (uint8_t*)malloc((K+2*B)*(K+2*B));
    uint8_t* responseList = (uint8_t*)malloc(NUM_PARTIES);
    uint8_t* tmpOutput = (uint8_t*)malloc(FILE_SIZE_BYTES);
    uint8_t* responsesIndexList = (uint8_t*)malloc(NUM_PARTIES);
    uint8_t* sharesIndex = (uint8_t*)malloc(K + 2*B);
    int tmp = 0;
    for (int i = 0; i < NUM_PARTIES; i++) {
        if (erasureIndexList[i] == 1) {
            responsesIndexList[i] = tmp;
            tmp++;
        } else {
            responsesIndexList[i] = 255;
        }
    }
    for (int i = 0; i < q; i++) {
        memset(responseList,0,NUM_PARTIES);
        memset(sharesIndex,0,NUM_PARTIES);
        int curr = 0; 
        int j = 0;
        while (curr < K + 2*B) {
            assert(j < NUM_PARTIES);
            if (PARTY_TO_POSITION_MAPPING[j][i] != 255 && erasureIndexList[j] == 1) {
                for (int a = 0; a < FILE_SIZE_BYTES; a++) {
                    shares[a][curr] = responses[responsesIndexList[j]][PARTY_TO_POSITION_MAPPING[j][i]][a];
                }
                responseList[j] = 1;
                sharesIndex[curr] = j + 1;
                curr++;
            }
            j++;
        }

        for (int j = 0; j < FILE_SIZE_BYTES; j++) {
            tmpOutput[j] = computeMultiPartyDecodingMalicious(sharesIndex, shares[j], K + 2*B, K, B);
        }

        XOR(output, tmpOutput, output, FILE_SIZE_BYTES);
    }

}

void assembleShamirResponses(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output, uint8_t*** coeffs_x, uint8_t*** coeffs_y) {
    int n = LOG_NUM_ENCODED_FILES;
    int x = LOG_NUM_ENCODED_FILES/2 + (LOG_NUM_ENCODED_FILES % 2 != 0);
    int y = n - x;
    int numResponses = NUM_PARTIES - R;
    int xpow = get2pow(x);
    int ypow = get2pow(y);
    uint8_t* tmpOutput = (uint8_t*)malloc(K*ENCODED_FILE_SIZE_BYTES);
    memset(tmpOutput,0,K*ENCODED_FILE_SIZE_BYTES);

    uint8_t* evalPoints = (uint8_t*)malloc(numResponses);
    uint8_t currInd = 0;
    for (int i = 0; i < numResponses; i++) {
        while (erasureIndexList[currInd] == 0) {
            currInd++;
        }
        evalPoints[i] = currInd + 1;
        currInd++;
    }
    
    uint8_t*** tmpShares = (uint8_t***)malloc(NUM_ROUNDS*sizeof(uint8_t**));
    for (int i = 0; i < NUM_ROUNDS; i++) {
        tmpShares[i] = (uint8_t**)malloc(2*numResponses*sizeof(uint8_t*));
        for (int j = 0; j < 2*numResponses; j ++) {
            tmpShares[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
            memset(tmpShares[i][j],0,ENCODED_FILE_SIZE_BYTES);
        }
    }

    // reconstruct derivatives: 
    for (int n = 0; n < NUM_ROUNDS; n++) {
        for (int i = 0; i < numResponses; i++) {
            for (int j = 0; j < xpow; j++) {
                uint8_t tmp = 0;
                for (int k = 1; k <= T + NUM_ROUNDS; k++) {
                    tmp ^= gf_mul(gf_mul((k%2), gf_pow(evalPoints[i],k-1)),coeffs_x[n][j][k]);
                }
                for (int k = 0; k < ENCODED_FILE_SIZE_BYTES; k++) {
                    tmpShares[n][2*i + 1][k] ^= gf_mul(tmp, responses[i][n][j*ENCODED_FILE_SIZE_BYTES + k]);
                }
            }
            for (int j = 0; j < ypow; j++) {
                uint8_t tmp = 0;
                for (int k = 1; k < T + NUM_ROUNDS; k++) {
                    tmp ^= gf_mul(gf_mul((k%2),gf_pow(evalPoints[i],k-1)),coeffs_y[n][j][k]);
                }
                for (int k = 0; k < ENCODED_FILE_SIZE_BYTES; k++) {
                    tmpShares[n][2*i + 1][k] ^= gf_mul(tmp, responses[i][n][(xpow + j)*ENCODED_FILE_SIZE_BYTES + k]);
                }
            }
            for (int k = 0; k < ENCODED_FILE_SIZE_BYTES; k++) {
                tmpShares[n][2*i + 1][k] ^= responses[i][n][(xpow + ypow)*ENCODED_FILE_SIZE_BYTES + k];
            }
            memcpy(tmpShares[n][2*i], &responses[i][n][(xpow + ypow + 1)*ENCODED_FILE_SIZE_BYTES], ENCODED_FILE_SIZE_BYTES); 
        }
    }
    
    uint8_t** shares = (uint8_t**)malloc(ENCODED_FILE_SIZE_BYTES* sizeof(uint8_t*));
    for (int i = 0; i < ENCODED_FILE_SIZE_BYTES; i++) {
        shares[i] = (uint8_t*)malloc(numResponses);
    }

    uint8_t** derivShares = (uint8_t**)malloc(ENCODED_FILE_SIZE_BYTES* sizeof(uint8_t*));
    for (int i = 0; i < ENCODED_FILE_SIZE_BYTES; i++) {
        derivShares[i] = (uint8_t*)malloc(numResponses);
    }

    for (int i = 0; i < NUM_ROUNDS; i++) {
        for (int j = 0; j < numResponses; j++) {
            for (int a = 0; a < ENCODED_FILE_SIZE_BYTES; a++) {
                shares[a][j] = tmpShares[i][2*j][a];
                derivShares[a][j] = tmpShares[i][2*j+1][a];
                if (i > 0) {
                    for (int b = 0; b < i; b++) {
                        shares[a][j] ^= gf_mul(tmpOutput[(K - 1 - b)*ENCODED_FILE_SIZE_BYTES + a], gf_pow(evalPoints[j], 2*T + K - 1 + 2*i - b));
                        derivShares[a][j] ^= gf_mul((2*T + K - 1 + 2*i - b) % 2,gf_mul(tmpOutput[(K - 1 - b)*ENCODED_FILE_SIZE_BYTES + a], gf_pow(evalPoints[j], 2*T + K - 1 + 2*i - b - 1)));
                    }
                }
            }
        }
        int funcDeg = 2*T + K - 1 + i;
        uint8_t* tmp = (uint8_t*)malloc(funcDeg + 1);
        for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
            if (B > 0) {
                hermiteInterpolationMalicious(evalPoints, numResponses, shares[j], derivShares[j], funcDeg, B, tmp);
            } else {
                hermiteInterpolationSemihonest(evalPoints, numResponses, shares[j], derivShares[j], funcDeg, tmp);
            }

            for (int k = 0; k < RHO; k++) {
                tmpOutput[(K - 1 - RHO*i - k)*ENCODED_FILE_SIZE_BYTES + j] = tmp[funcDeg - k];
            }
        }
        free(tmp);
    }
    memcpy(output, tmpOutput, FILE_SIZE_BYTES);
}

void assembleShamirResponsesSemiHonest(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output, uint8_t*** coeffs_x, uint8_t*** coeffs_y) {
    assembleShamirResponses(c,erasureIndexList,responses,output,coeffs_x,coeffs_y);
}

void assembleShamirResponsesMalicious(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output, uint8_t*** coeffs_x, uint8_t*** coeffs_y) {
    assembleShamirResponses(c,erasureIndexList,responses,output,coeffs_x,coeffs_y);
}

void assembleHollantiResponses(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output) {
    int numResponses = NUM_PARTIES - R;

    uint8_t* tmpOutput = (uint8_t*)malloc(K*ENCODED_FILE_SIZE_BYTES);
    memset(tmpOutput,0,K*ENCODED_FILE_SIZE_BYTES);

    uint8_t** shares = (uint8_t**)malloc(ENCODED_FILE_SIZE_BYTES* sizeof(uint8_t*));
    uint8_t* evalPoints = (uint8_t*)malloc(numResponses); 
    uint8_t* tmp = (uint8_t*)malloc(K + T - 1 + RHO);

    for (int i = 0; i < ENCODED_FILE_SIZE_BYTES; i++) {
        shares[i] = (uint8_t*)malloc(numResponses);
    }
    // encryptedFileSize x numResponses  
    for (int i = 0; i < NUM_ROUNDS; i++) {
        int curr = 1;
        for (int j = 0; j < numResponses; j++) {
            while (erasureIndexList[curr - 1] == 0) {
                curr++;
            }
            evalPoints[j] = curr;
            for (int a = 0; a < ENCODED_FILE_SIZE_BYTES; a++) {
                shares[a][j] = responses[j][i][a];
                if (i > 0) {
                    for (int b = 0; b < i; b++) {
                        // FIX THIS 
                        shares[a][j] ^= gf_mul(tmpOutput[(K - 1 - b)*ENCODED_FILE_SIZE_BYTES + a], gf_pow(curr, K + T - 1 + i - b));
                    }
                }
            }
            curr++; 
        }

        // decoding 
        for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
            if (B > 0) {
                lagrangeInterpolationMalicious(evalPoints, numResponses, shares[j], K + T + (RHO - 1)- 1, B, tmp);
            } else {
                lagrangeInterpolationSemihonest(evalPoints, numResponses, shares[j],  K + T + (RHO - 1)- 1, tmp);
            }
            for (int k = 0; k < RHO; k++) {
                tmpOutput[(K - 1 - i - k)*ENCODED_FILE_SIZE_BYTES + j] = tmp[K + T + RHO - 1 - 1 - k];
            }
        }
    }
    memcpy(output, tmpOutput, FILE_SIZE_BYTES);

    free(tmpOutput);
    for (int i = 0; i < ENCODED_FILE_SIZE_BYTES; i++) {
        free(shares[i]);
    }
    free(shares);
    free(tmp);
}

void assembleHollantiResponsesSemiHonest(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output) {
    assembleHollantiResponses(c, erasureIndexList, responses, output);
}

void assembleHollantiResponsesMalicious(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output) {
    assembleHollantiResponses(c, erasureIndexList, responses, output);
}

void assembleCDResponses(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output) {
    int q = NUM_CD_KEYS_NEEDED;
    int numResponses = NUM_PARTIES - R;
    uint8_t** shares = (uint8_t**)malloc(FILE_SIZE_BYTES* sizeof(uint8_t*));

    for (int i = 0; i < FILE_SIZE_BYTES; i++) {
        shares[i] = (uint8_t*)malloc(K + 2*B);
    }

    uint8_t* tmpOutput = (uint8_t*)malloc(FILE_SIZE_BYTES);
    uint8_t* responsesIndexList = (uint8_t*)malloc(NUM_PARTIES);
    uint8_t* evalPoints = (uint8_t*)malloc(K + 2*B);

    int t = 0;
    for (int i = 0; i < NUM_PARTIES; i++) {
        if (erasureIndexList[i] == 1) {
            responsesIndexList[i] = t;
            t++;
        } else {
            responsesIndexList[i] = 255;
        }
    }

    uint8_t* tmp = (uint8_t*)malloc(K);
    for (int i = 0; i < q; i++) {
        memset(evalPoints,0,K + 2*B);

        int curr = 0; 
        int j = 0;
        while (curr < K + 2*B) {
            assert(j < NUM_PARTIES);

            if (CD_PARTY_TO_POSITION_MAPPING[j][i] != 255 && erasureIndexList[j] == 1) {
                for (int a = 0; a < FILE_SIZE_BYTES; a++) {
                    shares[a][curr] = responses[responsesIndexList[j]][CD_PARTY_TO_POSITION_MAPPING[j][i]][a];
                }
                evalPoints[curr] = j + 1;
                curr++;
            }
            j++;
        }
        for (int j = 0; j < FILE_SIZE_BYTES; j++) {
            if (B > 0) {
                lagrangeInterpolationMalicious(evalPoints, K + 2*B, shares[j], K - 1, B, tmp);
            } else {
                lagrangeInterpolationSemihonest(evalPoints, K, shares[j], K - 1, tmp);
            }
            tmpOutput[j] = tmp[0];
        }

        XOR(output, tmpOutput, output, FILE_SIZE_BYTES);
    }
    free(tmp);
}

void assembleCDResponsesSemiHonest(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output) {
    assembleCDResponses(c,erasureIndexList,responses,output);
}

void assembleCDResponsesMalicious(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output) {
    assembleCDResponses(c,erasureIndexList,responses,output);
}

void calcDerivEvals(uint8_t** v, uint8_t evalPoint, uint8_t m, uint8_t t, uint8_t* output) {
    memset(output, 0, m); 
    for (int i = 0; i < m; i++){
        for (int j = 0; j < t + 1; j++) {
            output[i] ^=  (j == 0) ? 0 : gf_mul(gf_pow(v[j-1][i],j),gf_mul((j%2),gf_pow(evalPoint, j-1)));
        }
    }
}

void assembleWoodruffResponses(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output, uint8_t** v) {
    int numResponses = NUM_PARTIES - R;

    uint8_t* tmpOutput = (uint8_t*)malloc(FILE_SIZE_BYTES);
    memset(tmpOutput,0,FILE_SIZE_BYTES);

    uint8_t** shares = (uint8_t**)malloc(ENCODED_FILE_SIZE_BYTES* sizeof(uint8_t*));
    uint8_t* evalPoints = (uint8_t*)malloc(numResponses); 

    for (int i = 0; i < ENCODED_FILE_SIZE_BYTES; i++) {
        shares[i] = (uint8_t*)malloc(numResponses);
    }

    int curr = 1;
    for (int j = 0; j < numResponses; j++) {
        while (erasureIndexList[curr - 1] == 0) {
            curr++;
        }
        evalPoints[j] = curr;
        for (int a = 0; a < ENCODED_FILE_SIZE_BYTES; a++) {
            shares[a][j] = responses[j][0][a];
        }
        curr++; 
    }
    uint8_t* tmp = (uint8_t*)malloc(WOODRUFF_D*T + 1);
    if (WOODRUFF_DERIVATIVE) {


        uint8_t** derivShares = (uint8_t**)malloc(ENCODED_FILE_SIZE_BYTES* sizeof(uint8_t*));
        for (int i = 0; i < ENCODED_FILE_SIZE_BYTES; i++) {
            derivShares[i] = (uint8_t*)malloc(numResponses);
        }
        // reconstruct derivatives TODO
        uint8_t* derivEvals = (uint8_t*)malloc(WOODRUFF_M);
        for (int i = 0; i < ENCODED_FILE_SIZE_BYTES; i++) {
            for (int j = 0; j < numResponses; j++) {
                calcDerivEvals(v, evalPoints[j], WOODRUFF_M, T, derivEvals);
                for (int k = 0; k < WOODRUFF_M; k++) {
                    derivShares[i][j] ^= gf_mul(responses[j][k+1][i],derivEvals[k]);
                }
            }
        }

        for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
            if (B > 0) {
                hermiteInterpolationMalicious(evalPoints, numResponses, shares[j], derivShares[j], WOODRUFF_D*T, B, tmp);
            } else {
                hermiteInterpolationSemihonest(evalPoints, numResponses, shares[j], derivShares[j], WOODRUFF_D*T, tmp);
            }
            tmpOutput[j] = tmp[0];
        }

    } else {
        for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
            if (B > 0) {
                lagrangeInterpolationMalicious(evalPoints, numResponses, shares[j], WOODRUFF_D*T, B, tmp);
            } else {
                lagrangeInterpolationSemihonest(evalPoints, numResponses, shares[j], WOODRUFF_D*T, tmp);
            }
            tmpOutput[j] = tmp[0];
        }
    }
    memcpy(output, tmpOutput, FILE_SIZE_BYTES); 
}

void assembleWoodruffResponsesSemiHonest(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output, uint8_t** v) {
    assembleWoodruffResponses(c,erasureIndexList,responses,output,v);
}

void assembleWoodruffResponsesMalicious(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output, uint8_t** v) {
    assembleWoodruffResponses(c,erasureIndexList,responses,output,v);
}