#include <ctime> 
#include <openssl/rand.h>
#include <string.h>
#include <assert.h>
#include <math.h>

#include "server.h"
#include "params.h"
#include "common.h"
#include "utils.h"
#include "dpf_tree.h"
#include "shamir_dpf.h"
#include "multiparty_dpf.h"
#include "coding.h"

/* Setup for server. */
void initializeServer(server *s, int partyIndex, uint32_t logNumFiles, uint32_t fileSizeBytes, int isByzantine, int numThreads) {
    s->ctx = EVP_CIPHER_CTX_new();
    s->ctxThreads = (EVP_CIPHER_CTX **)malloc(numThreads*sizeof(EVP_CIPHER_CTX*));
    for (int i = 0; i < numThreads; i++) {
        s->ctxThreads[i] = EVP_CIPHER_CTX_new();
    }
    s->partyIndex = partyIndex;
    uint32_t numFiles = pow(2,logNumFiles);
    if (IS_HERMITE) {
        s->indexList = (uint8_t**)malloc(2 * numFiles * sizeof(uint8_t *));
       
        for (int i = 0; i < 2*numFiles; i++) {
            s->indexList[i] = (uint8_t*)malloc(fileSizeBytes);
            memset(s->indexList[i], 0, fileSizeBytes);
            
        } 
    } else {
        s->indexList = (uint8_t**)malloc(numFiles * sizeof(uint8_t *));
        for (int i = 0; i < numFiles; i++) {
            s->indexList[i] = (uint8_t*)malloc(fileSizeBytes);
            memset(s->indexList[i], 0, fileSizeBytes); 
        } 
    }
    s->isByzantine = isByzantine;
    s->numThreads = numThreads;
}

/* Free state of server. */
void freeServer(server *s) {
    EVP_CIPHER_CTX_free(s->ctx);
    free(s->ctxThreads);
    for (int i = 0; i < NUM_ENCODED_FILES; i++) {
        free(s->indexList[i]);
    }
    free(s->indexList);
}


/* Print state of server. */
void printServer(server *s) {
    printf("Printing contents of server %d:\n", s->partyIndex);
    if (s == NULL) printf("Server is empty\n");
    for (int i = 0; i < NUM_ENCODED_FILES; i++) {
        printf("row %d :", i);
        printBuffer(s->indexList[i], ENCODED_FILE_SIZE_BYTES);
    }
    if (IS_HERMITE) {
        for (int i = 0; i < NUM_ENCODED_FILES; i++) {
            printf("row %d :", NUM_ENCODED_FILES + i);
            printBuffer(s->indexList[NUM_ENCODED_FILES + i], ENCODED_FILE_SIZE_BYTES);
        }
    }
    printf("\n");
}

void runSingleDPFTreeQuery(server *s, uint8_t* key, uint8_t** result) {
    clock_t time;
    int partyIndex = (s->partyIndex) - 1;
    uint8_t* output = (uint8_t*)malloc(NUM_ENCODED_FILES);
    // runQuery here 
    evalAllDPF(s->ctx, NUM_PARTIES, partyIndex, LOG_NUM_ENCODED_FILES, key, ENCODED_FILE_SIZE_BYTES, &output);
    uint8_t* tmp = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
    memset(tmp,0,ENCODED_FILE_SIZE_BYTES);
    for (int i = 0; i < NUM_ENCODED_FILES; i++) {
        for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
            tmp[j] ^= gf_mul(output[i],(s->indexList[i])[j]);
        }
    }
    *result = tmp;
    free(output);
}

void runDPFTreeQuery(server *s, uint8_t** keys, int numKeys, uint8_t** result) {
    for (int i = 0; i < numKeys; i++) {
        runSingleDPFTreeQuery(s, keys[i], &result[i]);
    }
}

// @tmleong Use for benchmarking and in Server.go
void runOptimizedDPFTreeQuery(server *s, uint8_t* key, int numQueries, uint8_t** result) {
    clock_t time; 

    int partyIndex = (s->partyIndex) - 1;
    uint8_t** output = (uint8_t**)malloc(numQueries*sizeof(uint8_t*));

    for (int i = 0; i < numQueries; i++) {
        output[i] = (uint8_t*)malloc(NUM_ENCODED_FILES);
    }
    time = clock();

    evalAllOptimizedDPF(s->ctx, NUM_PARTIES, partyIndex, LOG_NUM_ENCODED_FILES, key, ENCODED_FILE_SIZE_BYTES, numQueries, output);


    time = clock() - time; 
    //printf("%f SECONDS to eval All w/ optimization\n", (float)time/CLOCKS_PER_SEC);
    for (int i = 0; i < numQueries; i++) {
        memset(result[i],0,ENCODED_FILE_SIZE_BYTES);
    }
    time = clock(); 
    if (s->isByzantine) {
        for (int i = 0; i < numQueries; i++) {
            gen_rand_bytes(result[i],ENCODED_FILE_SIZE_BYTES);
        }
    } else {
        for (int i = 0; i < NUM_ENCODED_FILES; i++) {
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                for (int k = 0; k < numQueries; k++) {
                    result[k][j] ^= gf_mul(output[k][i],(s->indexList[i][j]));
                }
            }
        }
    }
    time = clock() - time; 
    for (int i = 0; i < numQueries; i++) {
        free(output[i]);
    }
    free(output);
}

void runOptimizedMultiPartyDPFQuery(server *s, uint8_t* key, uint8_t** result) {
    clock_t time; 

    int partyIndex = (s->partyIndex) - 1;

    uint8_t** output = (uint8_t**)malloc(NUM_RSS_KEYS*sizeof(uint8_t*));

    for (int i = 0; i < NUM_RSS_KEYS; i++) {
        output[i] = (uint8_t*)malloc(NUM_ENCODED_FILES);
    }
    time = clock();  

    evalAllOptMultiPartyDPF(s->ctx, NUM_PARTIES, LOG_NUM_ENCODED_FILES, key, T, output);
    time = clock() - time; 
    //printf("%f SECONDS to eval All w/ optimization\n", (float)time/CLOCKS_PER_SEC);
    for (int i = 0; i < NUM_RSS_KEYS; i++) {
        memset(result[i],0,ENCODED_FILE_SIZE_BYTES);
    }

    time = clock(); 

    if (s->isByzantine) {
        for (int i = 0; i < NUM_RSS_KEYS; i++) {
            gen_rand_bytes(result[i],ENCODED_FILE_SIZE_BYTES);
        }
    } else {
        for (int i = 0; i < NUM_ENCODED_FILES; i++) {
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                for (int k = 0; k < NUM_RSS_KEYS; k++) {
                    result[k][j] ^= gf_mul(output[k][i],(s->indexList[i][j]));
                }
            }
        }
    }

    time = clock() - time; 
    for (int i = 0; i < NUM_RSS_KEYS; i++) {
        free(output[i]);
    }
    free(output);
}

void runSingleMultiPartyDPFQuery(server *s, uint8_t* key, uint8_t** result) {
    clock_t time;
    uint8_t* output = (uint8_t*)malloc(NUM_ENCODED_FILES);
    time = clock();
    evalAllMultiPartyDPF(s->ctx, NUM_PARTIES, LOG_NUM_ENCODED_FILES, key, &output);
    time = clock() - time; 
    time = clock();
    uint8_t* tmp = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
    memset(tmp,0,ENCODED_FILE_SIZE_BYTES);
    for (int i = 0; i < NUM_ENCODED_FILES; i++) {
        for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
            tmp[j] ^= gf_mul(output[i],(s->indexList[i])[j]);
        }
    }
    time = clock() - time; 
    *result = tmp;
    free(output);
}

void runMultiPartyDPFQuery(server *s, uint8_t** keys, int numKeys, uint8_t** result) {
    for (int i = 0; i < numKeys; i++) {
        runSingleMultiPartyDPFQuery(s, keys[i], &result[i]);
    }
}

void runOptShamirDPFQuery( server *s, uint8_t** keys, uint8_t** result) {
    clock_t time; 
    int n = LOG_NUM_ENCODED_FILES;
    int x = LOG_NUM_ENCODED_FILES/2 + (LOG_NUM_ENCODED_FILES % 2 != 0);
    int y = n - x;
    int xpow = get2pow(x);
    int ypow = get2pow(y);
    int derivRecordSize = (xpow + ypow)*ENCODED_FILE_SIZE_BYTES;
    for (int i = 0; i < NUM_ROUNDS; i++) {
        memset(result[i],0, derivRecordSize + 2*ENCODED_FILE_SIZE_BYTES);
    }

    if (s->isByzantine) {
        for (int i = 0; i < NUM_ROUNDS; i++) {
            gen_rand_bytes(result[i],derivRecordSize + 2*ENCODED_FILE_SIZE_BYTES);
        }
    } else {
        for (int i = 0; i < NUM_ENCODED_FILES; i++) {
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                uint32_t gamma = i & ((1 << (n/2)) - 1); 
                uint32_t delta = (i & (((1 << (n+1)/2) - 1) << n/2)) >> n/2;
                for (int k = 0; k < NUM_ROUNDS; k++) {
                    uint8_t fileItem = s->indexList[i][j];
                    uint8_t key_x = keys[k][xpow + gamma];
                    uint8_t key_y = keys[k][delta];

                    uint8_t fileItemy = gf_mul(key_y, fileItem); 
                    result[k][delta*(ENCODED_FILE_SIZE_BYTES) + j] ^= gf_mul(key_x,fileItem); // intermediate x sum 
                    result[k][(xpow + gamma)*ENCODED_FILE_SIZE_BYTES + j] ^= fileItemy; // intermediate y sum 
                    result[k][derivRecordSize + j] ^= gf_mul(keys[k][xpow + gamma],gf_mul(key_y,(s->indexList[NUM_ENCODED_FILES + i][j]))); // total sum
                    result[k][derivRecordSize + ENCODED_FILE_SIZE_BYTES + j] ^= gf_mul(key_x,fileItemy); // total sum  

                }
            }
        }
    }
}

void runOptShamirDPFQueryThread(server *s, uint8_t** keys, int threadNum, int startIndex, int endIndex, uint8_t** result) {
    clock_t time; 
    int n = LOG_NUM_ENCODED_FILES;
    int x = LOG_NUM_ENCODED_FILES/2 + (LOG_NUM_ENCODED_FILES % 2 != 0);
    int y = n - x;
    int xpow = get2pow(x);
    int ypow = get2pow(y);
    int derivRecordSize = (xpow + ypow)*ENCODED_FILE_SIZE_BYTES;

    for (int i = 0; i < NUM_ROUNDS; i++) {
        memset(result[i],0, derivRecordSize + 2*ENCODED_FILE_SIZE_BYTES);
        
    }

    if (s->isByzantine) {
        for (int i = startIndex; i < endIndex; i++) {
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                uint32_t gamma = i & ((1 << (n/2)) - 1); 
                uint32_t delta = (i & (((1 << (n+1)/2) - 1) << n/2)) >> n/2;
                for (int k = 0; k < NUM_ROUNDS; k++) {
                    uint8_t fileItem = s->indexList[i][j];
                    

                    uint8_t key_x = keys[k][xpow + gamma];
                    uint8_t key_y = keys[k][delta];

                    uint8_t fileItemy = gf_mul(key_y, fileItem);
                    

                    result[k][delta*(ENCODED_FILE_SIZE_BYTES) + j] ^= gf_mul(key_x,fileItem); // intermediate x sum 
                    result[k][(xpow + gamma)*ENCODED_FILE_SIZE_BYTES + j] ^= fileItemy; // intermediate y sum 
                    result[k][derivRecordSize + j] ^= gf_mul(keys[k][xpow + gamma],gf_mul(key_y,(s->indexList[NUM_ENCODED_FILES + i][j]))); // total sum
                    result[k][derivRecordSize + ENCODED_FILE_SIZE_BYTES + j] ^= gf_mul(key_x,fileItemy); // total sum

                }
            }
        }
    } else {
        for (int i = startIndex; i < endIndex; i++) {
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                uint32_t gamma = i & ((1 << (n/2)) - 1); 
                uint32_t delta = (i & (((1 << (n+1)/2) - 1) << n/2)) >> n/2;
                for (int k = 0; k < NUM_ROUNDS; k++) {
                    uint8_t fileItem = s->indexList[i][j];
                    

                    uint8_t key_x = keys[k][xpow + gamma];
                    uint8_t key_y = keys[k][delta];

                    uint8_t fileItemy = gf_mul(key_y, fileItem);
                    

                    result[k][delta*(ENCODED_FILE_SIZE_BYTES) + j] ^= gf_mul(key_x,fileItem); // intermediate x sum 
                    result[k][(xpow + gamma)*ENCODED_FILE_SIZE_BYTES + j] ^= fileItemy; // intermediate y sum 
                    result[k][derivRecordSize + j] ^= gf_mul(keys[k][xpow + gamma],gf_mul(key_y,(s->indexList[NUM_ENCODED_FILES + i][j]))); // total sum
                    result[k][derivRecordSize + ENCODED_FILE_SIZE_BYTES + j] ^= gf_mul(key_x,fileItemy); // total sum

                }
            }
        }
    }
}

void assembleShamirQueryThreadResults(server *s, uint8_t ***in, int numThreads, uint8_t **out) {
    int n = LOG_NUM_ENCODED_FILES;
    int x = LOG_NUM_ENCODED_FILES/2 + (LOG_NUM_ENCODED_FILES % 2 != 0);
    int y = n - x;
    int xpow = get2pow(x);
    int ypow = get2pow(y);
    int derivRecordSize = (xpow + ypow)*ENCODED_FILE_SIZE_BYTES;
    for (int i = 0; i < NUM_ROUNDS; i++) {
        memset(out[i], 0, derivRecordSize + 2*ENCODED_FILE_SIZE_BYTES);
        for (int j = 0; j < derivRecordSize + 2*ENCODED_FILE_SIZE_BYTES; j++) {
            for (int k = 0; k < numThreads; k++) {
                out[i][j] = out[i][j] ^ in[k][i][j];
            }
        }
    }
}

void runHollantiQuery(server *s, uint8_t** key, uint8_t** result) {
    clock_t time; 
    for (int i = 0; i < NUM_ROUNDS; i++) {
        memset(result[i],0,ENCODED_FILE_SIZE_BYTES);
    }

    time = clock(); 

    if (s->isByzantine) {
        for (int i = 0; i < NUM_ROUNDS; i++) {
            gen_rand_bytes(result[i],ENCODED_FILE_SIZE_BYTES);
        }
    } else {
        for (int i = 0; i < NUM_ENCODED_FILES; i++) {
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                for (int k = 0; k < NUM_ROUNDS; k++) {
                    result[k][j] ^= gf_mul(key[k][i],(s->indexList[i][j]));
                }
            }
        }
    }
    time = clock() - time; 
}

void runHollantiQueryThread(server *s, uint8_t** keys, int threadNum, int startIndex, int endIndex, uint8_t** result) {
    clock_t time; 
    for (int i = 0; i < NUM_ROUNDS; i++) {
        memset(result[i],0,ENCODED_FILE_SIZE_BYTES);
    }

    time = clock(); 

    if (s->isByzantine) {
        for (int i = startIndex; i < endIndex; i++) {
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                for (int k = 0; k < NUM_ROUNDS; k++) {
                    result[k][j] ^= gf_mul(keys[k][i],(s->indexList[i][j]));
                }
            }
        }
    } else {
        for (int i = startIndex; i < endIndex; i++) {
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                for (int k = 0; k < NUM_ROUNDS; k++) {
                    result[k][j] ^= gf_mul(keys[k][i],(s->indexList[i][j]));
                }
            }
        }
    }
    time = clock() - time; 
}

void assembleHollantiQueryThreadResults(server *s, uint8_t ***in, int numThreads, uint8_t **out) {
    for (int i = 0; i < NUM_ROUNDS; i++) {
        memset(out[i], 0, ENCODED_FILE_SIZE_BYTES);
        for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
            for (int k = 0; k < numThreads; k++) {
                out[i][j] = out[i][j] ^ in[k][i][j];
            }
        }
    }
}

void runOptimizedMultiPartyDPFQueryThread(server *s, uint8_t* key, int threadNum, int numThreads, uint8_t** result) {
    clock_t time; 

    uint8_t** output = (uint8_t**)malloc(NUM_RSS_KEYS*sizeof(uint8_t*));

    for (int i = 0; i < NUM_RSS_KEYS; i++) {
        output[i] = (uint8_t*)malloc(NUM_ENCODED_FILES);
    }
    time = clock();  
    evalAllOptMultiPartyDPFThread(s->ctxThreads[threadNum],NUM_PARTIES,LOG_NUM_ENCODED_FILES,key,T,output,threadNum,numThreads);
    time = clock() - time; 
    for (int i = 0; i < NUM_RSS_KEYS; i++) {
        memset(result[i],0,ENCODED_FILE_SIZE_BYTES);
    }

    time = clock(); 

    int mu_pow = ceil(log2(ceil((pow(2, LOG_NUM_ENCODED_FILES/2.0) * pow(2,(NUM_PARTIES-1)/2.0)))));
    uint64_t mu = (uint64_t)pow(2,mu_pow);
    uint64_t nu = (uint64_t)pow(2, LOG_NUM_ENCODED_FILES - mu_pow);
    int slice = nu / numThreads; 

    if (s->isByzantine) {
        for (int i = threadNum*slice*mu; i < (threadNum+1)*slice*mu; i++) {
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                for (int k = 0; k < NUM_RSS_KEYS; k++) {
                    result[k][j] ^= gf_mul(output[k][i],(s->indexList[i][j]));
                }
            }
        }
    } else {
        // only need to iterate thru the slice for the thread
        for (int i = threadNum*slice*mu; i < (threadNum+1)*slice*mu; i++) {
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                for (int k = 0; k < NUM_RSS_KEYS; k++) {
                    result[k][j] ^= gf_mul(output[k][i],(s->indexList[i][j]));
                }
            }
        }
    }

    time = clock() - time; 
    for (int i = 0; i < NUM_RSS_KEYS; i++) {
        free(output[i]);
    }
    free(output);
}

void assembleMultipartyDPFQueryThreadResults(server *s, uint8_t ***in, int numThreads, uint8_t **out) {
    for (int i = 0; i < NUM_RSS_KEYS; i++) {
        memset(out[i], 0, ENCODED_FILE_SIZE_BYTES);
        for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
            for (int k = 0; k < numThreads; k++) {
                out[i][j] = out[i][j] ^ in[k][i][j];
            }
        }
    }
}

void runCDQueryThread(server *s, uint8_t* key, int threadNum, int numThreads, uint8_t** result) {
    clock_t time; 

    uint8_t** output = (uint8_t**)malloc(NUM_CD_KEYS*sizeof(uint8_t*));

    for (int i = 0; i < NUM_CD_KEYS; i++) {
        output[i] = (uint8_t*)malloc(NUM_ENCODED_FILES);
    }
    time = clock();  
    evalAllCDThread(s->ctxThreads[threadNum],NUM_PARTIES,LOG_NUM_ENCODED_FILES,key,T,output,threadNum,numThreads);
    time = clock() - time; 
    for (int i = 0; i < NUM_CD_KEYS; i++) {
        memset(result[i],0,ENCODED_FILE_SIZE_BYTES);
        
    }

    time = clock(); 

    int mu_pow = ceil((double)(LOG_NUM_ENCODED_FILES/2)) + 3;
    uint64_t mu = (uint64_t)pow(2,mu_pow);
    uint64_t nu = (uint64_t)pow(2, LOG_NUM_ENCODED_FILES - mu_pow);
    int slice = nu / numThreads; 

    if (s->isByzantine) {
        for (int i = threadNum*slice*mu; i < (threadNum+1)*slice*mu; i++) {
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                for (int k = 0; k < NUM_CD_KEYS; k++) {
                    result[k][j] ^= gf_mul(output[k][i],(s->indexList[i][j]));
                }

            }
        }
    } else {
        // only need to iterate thru the slice for the thread
        for (int i = threadNum*slice*mu; i < (threadNum+1)*slice*mu; i++) {
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                for (int k = 0; k < NUM_CD_KEYS; k++) {
                    result[k][j] ^= gf_mul(output[k][i],(s->indexList[i][j]));
                }

            }
        }
    }

    time = clock() - time; 
    for (int i = 0; i < NUM_CD_KEYS; i++) {
        free(output[i]);
    }
    free(output);
}

void assembleCDQueryThreadResults(server *s, uint8_t ***in, int numThreads, uint8_t **out) {
    for (int i = 0; i < NUM_CD_KEYS; i++) {
        memset(out[i], 0, ENCODED_FILE_SIZE_BYTES);
        for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
            for (int k = 0; k < numThreads; k++) {
                out[i][j] = out[i][j] ^ in[k][i][j];
            }
        }
    }
}

void runOptimizedDPFTreeQueryThread(server *s, uint8_t* key, int threadNum, int numThreads, uint8_t** result) {
    clock_t time; 
    
    uint8_t** output = (uint8_t**)malloc(NUM_ROUNDS*sizeof(uint8_t*));

    for (int i = 0; i < NUM_ROUNDS; i++) {
        output[i] = (uint8_t*)malloc(NUM_ENCODED_FILES);
    }
    time = clock();  
    
    evalAllOptimizedDPFThread(s->ctxThreads[threadNum],NUM_PARTIES, s->partyIndex - 1, LOG_NUM_ENCODED_FILES, key, 1, NUM_ROUNDS, output, threadNum,numThreads);
    time = clock() - time; 
    for (int i = 0; i < NUM_ROUNDS; i++) {
        memset(result[i],0,ENCODED_FILE_SIZE_BYTES);
        
    }

    time = clock(); 

    int slice = NUM_ENCODED_FILES / numThreads;

    if (s->isByzantine) {
        for (int i = threadNum*slice; i < (threadNum+1)*slice; i++) {
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                for (int k = 0; k < NUM_ROUNDS; k++) {
                    result[k][j] ^= gf_mul(output[k][i],(s->indexList[i][j]));
                }
            }
        }
    } else {
        for (int i = threadNum*slice; i < (threadNum+1)*slice; i++) {
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                for (int k = 0; k < NUM_ROUNDS; k++) {
                    result[k][j] ^= gf_mul(output[k][i],(s->indexList[i][j]));
                }
            }
        }
    }

    time = clock() - time; 
    for (int i = 0; i < NUM_ROUNDS; i++) {
        free(output[i]);
    }
    free(output);
}



void assemblDPFTreeQueryThreadResults(server *s, uint8_t ***in, int numThreads, uint8_t **out) {
    for (int i = 0; i < NUM_ROUNDS; i++) {
        memset(out[i], 0, ENCODED_FILE_SIZE_BYTES);
        for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
            for (int k = 0; k < numThreads; k++) {
                out[i][j] = out[i][j] ^ in[k][i][j];
            }
        }
    }
}

void runWoodruffQueryThread(server *s, uint8_t* key, int threadNum, int startIndex, int endIndex, uint8_t** result) {
    for (int i = 0; i < 1; i++) {
        std::cout << i << "\n";
        memset(result[i], 0, ENCODED_FILE_SIZE_BYTES);
    }
    if (s->isByzantine) {
        uint8_t* tmp = (uint8_t*)malloc(WOODRUFF_M);
        for (int i = startIndex; i < endIndex; i++) {
            uint8_t* tmpFile = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
            memcpy(tmpFile,s->indexList[i],ENCODED_FILE_SIZE_BYTES);
            memset(tmp,0,WOODRUFF_M);
            for (int j = 0; j < WOODRUFF_D; j++) {
                tmp[MAPPING_INDEX[i][j]-1] = 1;
            }


            for (int j = 0; j < WOODRUFF_M; j++) {
                if (tmp[j] == 1) {
                    for (int k = 0; k < ENCODED_FILE_SIZE_BYTES; k++) {
                        tmpFile[k] = gf_mul(tmpFile[k],key[j]);
                    }
                }
            }
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                result[0][j] = result[0][j] ^ tmpFile[j];
            }

            free(tmpFile);
        }
    } else {
        uint8_t* tmp = (uint8_t*)malloc(WOODRUFF_M);
        for (int i = startIndex; i < endIndex; i++) {
            uint8_t* tmpFile = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
            memcpy(tmpFile,s->indexList[i],ENCODED_FILE_SIZE_BYTES);
            memset(tmp,0,WOODRUFF_M);
            for (int j = 0; j < WOODRUFF_D; j++) {
                tmp[MAPPING_INDEX[i][j]-1] = 1;
            }

            for (int j = 0; j < WOODRUFF_M; j++) {
                if (tmp[j] == 1) {
                    for (int k = 0; k < ENCODED_FILE_SIZE_BYTES; k++) {
                        tmpFile[k] = gf_mul(tmpFile[k],key[j]);
                    }
                }
            }
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                result[0][j] = result[0][j] ^ tmpFile[j];
            }

            free(tmpFile);
        }
    }

    if (WOODRUFF_DERIVATIVE) {
        uint8_t* tmpFile = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        for (int j = 0; j < WOODRUFF_M; j++) {
            // calculate the j'th partial derivative 
            for (int i = startIndex; i < endIndex; i++) {
                memcpy(tmpFile,s->indexList[i],ENCODED_FILE_SIZE_BYTES);
                uint8_t* tmp = (uint8_t*)malloc(WOODRUFF_M);
                memset(tmp,0,WOODRUFF_M);
                for (int j = 0; j < WOODRUFF_D; j++) {
                    tmp[MAPPING_INDEX[i][j]-1] = 1;
                }
                if (tmp[j] == 1) { // if the current file is contained in the partial
                    for (int k = 0; k < WOODRUFF_M; k++) {
                        if ((k != j) && (tmp[k] == 1)) {
                            for (int a = 0; a < ENCODED_FILE_SIZE_BYTES; a++) {
                                tmpFile[a] = gf_mul(tmpFile[a],key[k]);
                            }
                            for (int i = 0; i < ENCODED_FILE_SIZE_BYTES; i++) {
                                result[j+1][i] = result[j+1][i] ^ tmpFile[i];
                            }
                        }
                    }
                }
            }
        }
        free(tmpFile);
    }
}

void assembleWoodruffQueryThreadResults(server *s, uint8_t ***in, int numThreads, uint8_t **out) {
    if (WOODRUFF_DERIVATIVE) {
        for (int i = 0; i < WOODRUFF_M + 1; i++) {
            memset(out[i], 0, ENCODED_FILE_SIZE_BYTES);
            for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
                for (int k = 0; k < numThreads; k++) {
                    out[i][j] = out[i][j] ^ in[k][i][j];
                }
            }
        }
    } else {
        memset(out[0], 0, ENCODED_FILE_SIZE_BYTES);
        for (int j = 0; j < ENCODED_FILE_SIZE_BYTES; j++) {
            for (int k = 0; k < numThreads; k++) {
                out[0][j] = out[0][j] ^ in[k][0][j];
            }
        }
    }
}

