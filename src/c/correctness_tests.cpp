#include <iostream>
#include <cassert>
#include <cstring>
#include <math.h>  
#include <ctime>   

#include "utils.h"
#include "coding.h"
#include "params.h"

#include "dpf_tree.h"
#include "client.h"
#include "shamir_dpf.h"
#include "multiparty_dpf.h"
#include "woodruff.h"
#include "interpolation.h"

void runDPFTreeCorrectnessTests(int log_domainSize, int p, std::vector<uint8_t> finalCW_values) {  
    clock_t time; 
    
    static EVP_CIPHER_CTX *ctx;
    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    assert(finalCW_values.size() == p - 1); 

    uint128_t index = 2; 
    int dataSize = 2; 
    int keyLength = calcDPFTreeKeyLength(p,log_domainSize);
    uint8_t** keys = (uint8_t**)malloc(p*sizeof(uint8_t*));
    for (int i = 0 ; i < p; i++) {
        keys[i] = (uint8_t*)malloc(keyLength);
    }
    time = clock(); 
    genDPF(ctx, log_domainSize, index, dataSize, finalCW_values, p, &keys);
    time = clock() - time;

    //printf("%f SECONDS FOR GEN DPF WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,log_domainSize);
    int domainSize = pow(2,log_domainSize);
    uint8_t** evalOutput = (uint8_t**)malloc(p*sizeof(uint8_t*));
    uint8_t** evalAllOutput = (uint8_t**)malloc(p*sizeof(uint8_t*));
    for (int i = 0; i < p; i++) {
        evalOutput[i] = (uint8_t*)malloc(domainSize);
        evalAllOutput[i] = (uint8_t*)malloc(domainSize);
    }
    for (int i = 0; i < p; i++) {
        time = clock(); 
        for (int j = 0; j < domainSize; j++) {
            evalDPF(ctx, p, i, log_domainSize, keys[i], j, dataSize, &evalOutput[i][j]);
        }
        time = clock() - time;
        //printf("%f SECONDS FOR EVAL DPF WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,log_domainSize);
        time = clock(); 
        evalAllDPF(ctx, p, i, log_domainSize, keys[i], dataSize, &evalAllOutput[i]);
        time = clock() - time;
        printf("%f SECONDS FOR EVALALL DPF WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,log_domainSize);
    }

    // check eval Output and evalAllOutput are the same 
    for (int i = 0; i < p; i++) {
        for (int j = 0; j < domainSize; j++) {
            assert(evalOutput[i][j] == evalAllOutput[i][j]); 
        }
    }

    // check randomness vectors are properly formatted
    for (int i = 1; i < p; i++) {
        for (int j = 0; j < domainSize; j++) {
            assert(evalAllOutput[0][j] == (j == index) ? evalAllOutput[i][j] ^ finalCW_values[i-1] : evalAllOutput[i][j]);
            // if (j == index) {
            //     assert(evalAllOutput[0][j] ^ finalCW_values[i-1] == evalAllOutput[i][j]);
            // } else {
            //     assert(evalAllOutput[0][j] == evalAllOutput[i][j]);   
            // }
        }
    }

    // free memory
    for (int i = 0; i < p; i++) {
        free(evalOutput[i]);
        free(evalAllOutput[i]);
    }

    free(evalOutput);
    free(evalAllOutput);
    EVP_CIPHER_CTX_free(ctx);
}

void runOptimizedDPFTreeCorrectnessTests() { 
    clock_t time;
    int p = 4;
    int log_domainSize = 16; 
    int numQueries = 2; 
    std::vector<uint8_t> finalCW_values;
    for (int i = 0; i < numQueries; i++) {
        for (int j = 2; j <= p; j++) {
            finalCW_values.push_back(gf_pow(j,i + 1) ^ 1);
        } 
    }
    
    static EVP_CIPHER_CTX *ctx;
    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    assert(finalCW_values.size() == numQueries*(p - 1)); 

    uint128_t index = 1; 
    int dataSize = 2; 
    int keyLength = calcOptimizedDPFTreeKeyLength(p,log_domainSize, numQueries);
    uint8_t** keys = (uint8_t**)malloc(p*sizeof(uint8_t*));
    for (int i = 0 ; i < p; i++) {
        keys[i] = (uint8_t*)malloc(keyLength);
    }
    //time = clock(); 
    genOptimizedDPF(ctx, log_domainSize, index, dataSize, finalCW_values, p, numQueries, &keys);
    //time = clock() - time;

    //printf("%f SECONDS FOR GEN DPF WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,log_domainSize);
    int domainSize = pow(2,log_domainSize);
    uint8_t*** evalAllOutput = (uint8_t***)malloc(p*sizeof(uint8_t**));
    for (int i = 0; i < p; i++) {
        evalAllOutput[i] = (uint8_t**)malloc(numQueries*sizeof(uint8_t*));
        for (int j = 0; j < numQueries; j++) {
            evalAllOutput[i][j] = (uint8_t*)malloc(domainSize);
        }
    }

    for (int i = 0; i < p; i++) {
        time = clock(); 
        evalAllOptimizedDPF(ctx, p, i, log_domainSize, keys[i], dataSize, numQueries, evalAllOutput[i]);

        time = clock() - time;
        printf("%f SECONDS FOR EVALALL OPTIMIZED DPF WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,log_domainSize);
    }

    // check randomness vectors are properly formatted
    for (int i = 1; i < p; i++) {
        for (int k = 0; k < numQueries; k++) {
            for (int j = 0; j < domainSize; j++) {
                assert(evalAllOutput[0][k][j] == (j == index) ? evalAllOutput[i][k][j] ^ finalCW_values[k*(p - 1) + i-1] : evalAllOutput[i][k][j]);
            }
        }
    }

    // free memory
    // for (int i = 0; i < p; i++) {
    //     free(evalAllOutput[i]);
    // }

    // free(evalAllOutput);
    EVP_CIPHER_CTX_free(ctx);
}

void runShamirDPFCorrectnessTests(int log_domainSize, int t, int p) {
    clock_t time; 
    int domainSize = pow(2,log_domainSize);
    uint128_t index = 0; 
    int dataSize = 2; 
    int keyLength = 2*log_domainSize;
    uint8_t** keys = (uint8_t**)malloc(p*sizeof(uint8_t*));
    for (int i = 0 ; i < p; i++) {
        keys[i] = (uint8_t*)malloc(keyLength);
    }

    genShamirDPF(log_domainSize, index, 1, dataSize, t, p, &keys);

    uint8_t** evalOutput = (uint8_t**)malloc(p*sizeof(uint8_t*));
    uint8_t** evalAllOutput = (uint8_t**)malloc(p*sizeof(uint8_t*));
    for (int i = 0; i < p; i++) {
        evalOutput[i] = (uint8_t*)malloc(domainSize);
        evalAllOutput[i] = (uint8_t*)malloc(domainSize);
    }

    for (int i = 0; i < p; i++) {
        time = clock(); 
        for (int j = 0; j < domainSize; j++) {
            evalShamirDPF(p, i, log_domainSize, keys[i], j, dataSize, &evalOutput[i][j]);
        }
        time = clock() - time;
        //printf("%f SECONDS FOR EVAL SHAMIRDPF WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,log_domainSize);
        time = clock(); 
        evalAllShamirDPF(p, i, log_domainSize, keys[i], dataSize, &evalAllOutput[i]);
        time = clock() - time;
        //printf("%f SECONDS FOR EVALALL SHAMIRDPF WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,log_domainSize);
    }

    // check eval Output and evalAllOutput are the same 
    for (int i = 0; i < p; i++) {
        for (int j = 0; j < domainSize; j++) {
            assert(evalOutput[i][j] == evalAllOutput[i][j]); 
        }
    }

    // Check Whether Decoding of Responses is correct 
    // Should decode to 0 on non special points 
    // And decode 1 on special index
    uint8_t** shares = (uint8_t**)malloc(domainSize*sizeof(uint8_t*));
    for (int i = 0; i < domainSize; i++) {
        shares[i] = (uint8_t*)malloc(p);
    } 
    uint8_t* vandermondeMat = (uint8_t*)malloc(p*p);
    gen_encode_matrix(vandermondeMat,p,p);
    uint8_t* decodeMat = (uint8_t*)malloc(p*p);
    gf_invert_matrix(vandermondeMat, decodeMat, p);

    for (int i = 0; i < domainSize; i++) {
        for (int j = 0; j < p; j++) {
            shares[i][j] = evalAllOutput[j][i]; 
        }
        uint8_t output;
        output = computeDecoding(decodeMat, shares[i], p, 0); 

        assert(output == (i == index)? 1 : 0);
    }

    // free memory
    for (int i = 0; i < p; i++) {
        free(evalOutput[i]);
        free(evalAllOutput[i]);
    }

    free(evalOutput);
    free(evalAllOutput);
    for (int i = 0 ; i < p; i++) {
        free(keys[i]); 
    }
    free(keys); 
}

void runClientDPFTreeOptCorrectnessTests(int logNumFiles, int fileSizeBytes, uint128_t index, int k, int r, int b, int rho, int checkMac, int numThreads) { 
    clock_t time; 
    int numFiles = pow(2,logNumFiles);
    setSystemParams(logNumFiles, fileSizeBytes, 1, k, r, b, rho, checkMac, 0);
    int p = NUM_PARTIES; 
    // initialize client
    client c;
    initialize_client(&c,logNumFiles,FILE_SIZE_BYTES);

    // initialize servers 
    server servers[p];
    int currByzantine = 0;
    for (int i = p-1; i >= 0; i--) {
        int isByzantine = 0;
        if (currByzantine < b) {
            isByzantine = 1;
            currByzantine++;
        }
        //printf("IS BYZANTINE %d\n",isByzantine);
        initializeServer(&servers[i],i+1,LOG_NUM_ENCODED_FILES,ENCODED_FILE_SIZE_BYTES, isByzantine, numThreads);
        encode_within_files_server(&c, &servers[i]);
        //printServer(&servers[i]);
    }

    // prepare keys 
    int keyLength = calcOptimizedDPFTreeKeyLength(p,LOG_NUM_ENCODED_FILES,NUM_ROUNDS);
    //printf("PARAMS %d %d %d\n",p,LOG_NUM_ENCODED_FILES,NUM_ROUNDS);
    //printf("KEY LENGTH %d\n",keyLength);
    uint8_t** keys = (uint8_t**)malloc(p*sizeof(uint8_t*));
    for (int j = 0 ; j < p; j++) {
        keys[j] = (uint8_t*)malloc(keyLength);
    }

    time = clock();
    generate_opt_DPF_tree_query(&c, index, &keys);
    time = clock() - time; 
    printf("%f SECONDS TO GEN DPF OPTIMIZED WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,LOG_NUM_FILES);

    uint8_t*** responses  = (uint8_t***)malloc(p*sizeof(uint8_t**));
    //printf("Gets Here\n");
    for (int i = 0; i < p; i++) {
        responses[i] = (uint8_t**)malloc(NUM_ROUNDS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_ROUNDS; j++) {
            responses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        }
    }

    uint8_t*** threadResponses  = (uint8_t***)malloc(p*sizeof(uint8_t**));
    //printf(“Gets Here\n”);
    for (int i = 0; i < p; i++) {
        threadResponses[i] = (uint8_t**)malloc(NUM_ROUNDS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_ROUNDS; j++) {
            threadResponses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        }
    }

    uint8_t*** perThread  = (uint8_t***)malloc(numThreads*sizeof(uint8_t**));
    //printf(“Gets Here\n”);
    for (int i = 0; i < numThreads; i++) {
        perThread[i] = (uint8_t**)malloc(NUM_ROUNDS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_ROUNDS; j++) {
            perThread[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        }
    }

    // run queries on each server 
    for (int i = 0; i < p; i++) {
        time = clock();
        runOptimizedDPFTreeQuery(&servers[i], keys[i], NUM_ROUNDS, responses[i]);
        time = clock() - time; 
        printf("%f SECONDS TO RUN DPF TREE QUERY OPTIMIZED WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,LOG_NUM_FILES);
        for (int j = 0; j < numThreads; j++) {
            time = clock();
            runOptimizedDPFTreeQueryThread(&servers[i],keys[i],j,servers[i].numThreads,perThread[j]);
            time = clock() - time;
            printf("%f SECONDS TO RUN DPF TREE QUERY OPTIMIZED THREAD WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,LOG_NUM_FILES); 
            //runOptShamirDPFQueryThread(&servers[i], keys[i], j, j*slice, (j+1)*slice, perThread[j]);
        } 
        assemblDPFTreeQueryThreadResults(&servers[i],perThread,numThreads,threadResponses[i]);
    }

    // for (int i =0; i < p; i++) {
    //     for (int j = 0; j < NUM_ROUNDS; j++) {
    //         printBuffer(responses[i][j],ENCODED_FILE_SIZE_BYTES);
    //         printBuffer(threadResponses[i][j],ENCODED_FILE_SIZE_BYTES);
    //         // for (int k = 0; k < ENCODED_FILE_SIZE_BYTES; k++) {
    //         //     assert(responses[i][j][k] == threadResponses[i][j][k]);
    //         // }
    //     }
    // }
    //printf("PARTY1\n");
    // assemble query response 
    time = clock();
    int numErasures = r; 
    int numResponses = p - numErasures; 

    int erasedIndex = 0; //chosen randomly 
    uint8_t* erasureIndexList = (uint8_t*)malloc(p);
    for (int i = 0; i < p; i++) {
        erasureIndexList[i] = (i < numErasures) ? 0 : 1;
    }
    //printf("PARTY2\n");
    //printBuffer(erasureIndexList,p);
    uint8_t* vandermondeMat = (uint8_t*)malloc(p*(k+1));
    gen_encode_matrix(vandermondeMat,p,k+1);
    uint8_t* decodeMat = (uint8_t*)malloc((k+1)*(k+1));
    uint8_t*** testResponses  = (uint8_t***)malloc(numResponses*sizeof(uint8_t**));
    for (int i = 0; i < numResponses; i++) {
        testResponses[i] = (uint8_t**)malloc(NUM_ROUNDS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_ROUNDS; j++) {
            testResponses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        }
    }
// printf("PARTY3\n");

    int curr = 0;
    for (int i = 0; i < p; i++) {
        if (erasureIndexList[i]!= 0) {
            for (int j = 0 ; j < NUM_ROUNDS; j++) {
                memcpy(testResponses[curr][j],responses[i][j],ENCODED_FILE_SIZE_BYTES);
                //testResponses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
            }
            curr++;
        }
    }
    //printf("PARTY4\n");

    uint8_t* test = (uint8_t*)malloc(FILE_SIZE_BYTES);
    assembleDPFTreeQueryResponses(&c, erasureIndexList, testResponses, test); 
    // if (b > 0) {
    //     assembleDPFTreeQueryResponsesMalicious(&c, erasureIndexList, testResponses, test); 
    // } else {
    //     assembleDPFTreeQueryResponsesSemiHonest(&c, erasureIndexList, testResponses, test); 
    // }
    //printf("PARTY5\n");
    time = clock() - time; 
    //printf("%f SECONDS TO DECODE W ONE ERASURE WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,logNumFiles);
    //printf("PRINTING TEST\n");

    printBuffer(test,PAYLOAD_SIZE_BYTES);
    for (int i = 0; i < PAYLOAD_SIZE_BYTES; i++) {
        assert(test[i] == c.unencoded_files[index][i]);
    }

    // uint8_t* test_input = (uint8_t*)malloc(PAYLOAD_SIZE_BYTES);
    // memset(test_input, 2, PAYLOAD_SIZE_BYTES);

    //printf("PARTY6\n");
    free(vandermondeMat);
    free(decodeMat);
    free(erasureIndexList);
    free(test);
    free_client(&c);
    for (int i = 0; i < p; i++) {
        freeServer(&servers[i]);
    }
    for (int i = 0; i < p; i++) {
        free(keys[i]);
    }
   //printf("PARTY7\n");
    free(keys);
    for (int i = 0; i < p; i++) {
        for (int j = 0 ; j < NUM_ROUNDS; j++) {
            free(responses[i][j]);
        }
        free(responses[i]);
    }
    //printf("PARTY8\n");
    free(responses);
    for (int i = 0; i < numResponses; i++) {
        for (int j = 0 ; j < NUM_ROUNDS; j++) {
            free(testResponses[i][j]);
        }
        free(testResponses[i]);
    }
    //printf("PARTY9\n");
    free(testResponses);
    //printf("PARTY10\n");
}

void runClientMultiPartyPirTests(int logNumFiles, int fileSizeBytes, uint128_t index, int k, int t, int r, int b, int rho, int checkMac, int numThreads) {
    clock_t time;
    // int p = t + k + r + (2*b);
    //int numFiles = pow(2,logNumFiles);
    // void setSystemParams(int logNumFiles, int fileSizeBytes, int p, int t, int k, int r, int b, int encodeAcross)
    //printf("%d\n", p);
    // setSystemParams(logNumFiles, fileSizeBytes, p, t, k, r, b, 1, 0, 0);
    setSystemParams(logNumFiles, fileSizeBytes, t, k, r, b, rho, checkMac, 1);
    int p = NUM_PARTIES; 
    // initialize client
    client c;
    initialize_client(&c,logNumFiles,fileSizeBytes);
    // initialize servers
    server servers[p]; // TODO 
    int currByzantine = 0;
    for (int i = p-1; i >= 0; i--) {
        int isByzantine = 0;
        if (currByzantine < b) {
            isByzantine = 1;
            currByzantine++;
        }
        initializeServer(&servers[i],i+1,LOG_NUM_ENCODED_FILES,ENCODED_FILE_SIZE_BYTES, isByzantine, numThreads);
        encode_across_files_server(&c, &servers[i]);
        //printServer(&servers[i]);
    }
    // for (int i = 0; i < p; i++) {
    //     printServer(&servers[i]);
    // }

    // prepare keys
    int keyLength = calcMultiPartyOptDPFKeyLength(p,LOG_NUM_ENCODED_FILES,t);
    //printf(“PARAMS %d %d %d\n”,p,LOG_NUM_ENCODED_FILES,NUM_ROUNDS);
    // printf("KEY LENGTH %d\n",keyLength);
    uint8_t** keys = (uint8_t**)malloc(p*sizeof(uint8_t*));
    for (int j = 0 ; j < p; j++) {
        keys[j] = (uint8_t*)malloc(keyLength);
    }
    time = clock();
    generateMultiPartyDPFQuery(&c, index, &keys);
    time = clock() - time;
    printf("%f SECONDS TO GEN DPF OPTIMIZED WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,LOG_NUM_FILES);

    // for (int i = 0; i < p; i++) {
    //     printBuffer(keys[i],keyLength);
    // }
    uint8_t*** responses  = (uint8_t***)malloc(p*sizeof(uint8_t**));
    //printf(“Gets Here\n”);
    for (int i = 0; i < p; i++) {
        responses[i] = (uint8_t**)malloc(NUM_RSS_KEYS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_RSS_KEYS; j++) {
            responses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        }
    }

    uint8_t*** threadResponses  = (uint8_t***)malloc(p*sizeof(uint8_t**));
    //printf(“Gets Here\n”);
    for (int i = 0; i < p; i++) {
        threadResponses[i] = (uint8_t**)malloc(NUM_RSS_KEYS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_RSS_KEYS; j++) {
            threadResponses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        }
    }

    uint8_t*** perThread  = (uint8_t***)malloc(numThreads*sizeof(uint8_t**));
    //printf(“Gets Here\n”);
    for (int i = 0; i < numThreads; i++) {
        perThread[i] = (uint8_t**)malloc(NUM_RSS_KEYS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_RSS_KEYS; j++) {
            perThread[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        }
    }

    // run queries on each server
    for (int i = 0; i < p; i++) {
        time = clock();
        //runOptimizedMultiPartyDPFQuery(&servers[i], keys[i], responses[i]);
        time = clock() - time;
        printf("%f SECONDS TO RUN DPF TREE QUERY OPTIMIZED WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,LOG_NUM_FILES);
        for (int j = 0; j < numThreads; j++) {
            runOptimizedMultiPartyDPFQueryThread(&servers[i],keys[i],j,servers[i].numThreads,perThread[j]);
            //runOptShamirDPFQueryThread(&servers[i], keys[i], j, j*slice, (j+1)*slice, perThread[j]);
        }
        assembleMultipartyDPFQueryThreadResults(&servers[i],perThread,numThreads,threadResponses[i]);
        //assembleShamirQueryThreadResults(&servers[i], perThread, numThreads, threadResponses[i]);
    }

    // check threading
    // for (int i =0; i < p; i++) {
    //     for (int j = 0; j < NUM_RSS_KEYS; j++) {
    //         for (int k = 0; k < ENCODED_FILE_SIZE_BYTES; k++) {
    //             assert(responses[i][j][k] == threadResponses[i][j][k]);
    //         }
    //     }
    // }
    printf("THREAD CHECK PASSED\n");


    // assemble query response
    time = clock();
    int numErasures = r;
    int numResponses = p - numErasures;
    uint8_t* erasureIndexList = (uint8_t*)malloc(p);
    for (int i = 0; i < p; i++) {
        erasureIndexList[i] = (i < numErasures) ? 0 : 1;
    }
    //printBuffer(erasureIndexList,p);
    //uint8_t* vandermondeMat = (uint8_t*)malloc(p*(k+1));
    //gen_encode_matrix(vandermondeMat,p,k+1);
    //uint8_t* decodeMat = (uint8_t*)malloc((k+1)*(k+1));
    uint8_t*** testResponses  = (uint8_t***)malloc(numResponses*sizeof(uint8_t**));
    for (int i = 0; i < numResponses; i++) {
        testResponses[i] = (uint8_t**)malloc(NUM_RSS_KEYS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_RSS_KEYS; j++) {
            testResponses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        }
    }

    int curr = 0;

    for (int i = 0; i < p; i++) {
        if (erasureIndexList[i]!= 0) {
            for (int j = 0 ; j < NUM_RSS_KEYS; j++) {
                //printf("BEFORE COPY\n");
                //printBuffer(responses[i][j], ENCODED_FILE_SIZE_BYTES);
                memcpy(testResponses[curr][j],threadResponses[i][j],ENCODED_FILE_SIZE_BYTES);
                //testResponses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
            }
            curr++;
        }
    }
    // for (int i = 0; i < numResponses; i++) {
    //     for (int j = 0; j < NUM_RSS_KEYS; j++) {
    //         printf("PRINTING PARTY %d RESPONSE %d\n", i + 1, j);
    //         printBuffer(testResponses[i][j], ENCODED_FILE_SIZE_BYTES);
    //     }
    // }
    // printf("\n\n\n");
    uint8_t* test = (uint8_t*)malloc(FILE_SIZE_BYTES);
    memset(test,0,FILE_SIZE_BYTES);
    assembleMultiPartyResponses(&c, erasureIndexList, testResponses, test);
    // if (b > 0) {
    //     assembleMultiPartyResponsesMalicious(&c, erasureIndexList, testResponses, test);
    // } else {
    //     assembleMultiPartyResponsesSemiHonest(&c, erasureIndexList, testResponses, test);
    // }
    time = clock() - time;
    //printf(“%f SECONDS TO DECODE W ONE ERASURE WITH LOG DOMAIN SIZE %d\n”, (float)time/CLOCKS_PER_SEC,logNumFiles);

    printBuffer(test,FILE_SIZE_BYTES);

    for (int i = 0; i < FILE_SIZE_BYTES; i++) {
        assert(test[i] == c.unencoded_files[index][i]);
    }

    free(keys);
    freeParams();
}

void runCDPirTests(int logNumFiles, int fileSizeBytes, uint128_t index, int k, int t, int r, int b, int rho, int checkMac, int numThreads) {
    clock_t time;
    // int p = t + k + r + (2*b) + 1;
    //int numFiles = pow(2,logNumFiles);
    // void setSystemParams(int logNumFiles, int fileSizeBytes, int p, int t, int k, int r, int b, int encodeAcross)
    //printf("%d\n", p);
    // setSystemParams(logNumFiles, fileSizeBytes, p, t, k, r, b, 1, 0, 0);
    setSystemParams(logNumFiles, fileSizeBytes, t, k, r, b, rho, checkMac, 4);
    int p = NUM_PARTIES; 
    // initialize client
    client c;
    initialize_client(&c,logNumFiles,fileSizeBytes);
    // initialize servers
    server servers[p]; // TODO 
    int currByzantine = 0;
    for (int i = p-1; i >= 0; i--) {
        int isByzantine = 0;
        if (currByzantine < b) {
            isByzantine = 1;
            currByzantine++;
        }
        initializeServer(&servers[i],i+1,LOG_NUM_ENCODED_FILES,ENCODED_FILE_SIZE_BYTES, isByzantine, numThreads);
        encode_across_files_server(&c, &servers[i]);
        //printServer(&servers[i]);
    }
    // for (int i = 0; i < p; i++) {
    //     printServer(&servers[i]);
    // }

    // prepare keys
    int keyLength = calcCDDPFKeyLength(p,LOG_NUM_ENCODED_FILES,t,NUM_CD_KEYS_NEEDED,NUM_CD_KEYS);
    //printf("PARAMS %d %d %d %d %d\n",p,LOG_NUM_ENCODED_FILES,t,NUM_CD_KEYS_NEEDED,NUM_CD_KEYS);
    //printf("KEY LENGTH %d\n",keyLength);
    uint8_t** keys = (uint8_t**)malloc(p*sizeof(uint8_t*));
    for (int j = 0 ; j < p; j++) {
        keys[j] = (uint8_t*)malloc(keyLength);
    }
    time = clock();
    generateCDQuery(&c, index, &keys);
    time = clock() - time;
    printf("%f SECONDS TO GEN DPF OPTIMIZED WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,LOG_NUM_FILES);

    // for (int i = 0; i < p; i++) {
    //     printBuffer(keys[i],keyLength);
    // }
    uint8_t*** responses  = (uint8_t***)malloc(p*sizeof(uint8_t**));
    //printf(“Gets Here\n”);
    for (int i = 0; i < p; i++) {
        responses[i] = (uint8_t**)malloc(NUM_CD_KEYS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_CD_KEYS; j++) {
            responses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        }
    }

    uint8_t*** threadResponses  = (uint8_t***)malloc(p*sizeof(uint8_t**));
    //printf(“Gets Here\n”);
    for (int i = 0; i < p; i++) {
        threadResponses[i] = (uint8_t**)malloc(NUM_CD_KEYS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_CD_KEYS; j++) {
            threadResponses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        }
    }

    uint8_t*** perThread  = (uint8_t***)malloc(numThreads*sizeof(uint8_t**));
    //printf(“Gets Here\n”);
    for (int i = 0; i < numThreads; i++) {
        perThread[i] = (uint8_t**)malloc(NUM_CD_KEYS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_CD_KEYS; j++) {
            perThread[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        }
    }

    // run queries on each server
    for (int i = 0; i < p; i++) {
        //time = clock();
        //runOptimizedMultiPartyDPFQuery(&servers[i], keys[i], responses[i]);
        //time = clock() - time;
        //printf("%f SECONDS TO RUN DPF CD732 QUERY OPTIMIZED WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,LOG_NUM_FILES);
        for (int j = 0; j < numThreads; j++) {
            runCDQueryThread(&servers[i],keys[i],j,servers[i].numThreads,perThread[j]);
            //runOptShamirDPFQueryThread(&servers[i], keys[i], j, j*slice, (j+1)*slice, perThread[j]);
        }
        assembleCDQueryThreadResults(&servers[i],perThread,numThreads,threadResponses[i]);
        //assembleShamirQueryThreadResults(&servers[i], perThread, numThreads, threadResponses[i]);
    }

    //check threading
    // for (int i =0; i < p; i++) {
    //     for (int j = 0; j < NUM_CD_KEYS; j++) {
    //         printBuffer(threadResponses[i][j],ENCODED_FILE_SIZE_BYTES);
    //         // for (int k = 0; k < ENCODED_FILE_SIZE_BYTES; k++) {
    //         //     assert(responses[i][j][k] == threadResponses[i][j][k]);
    //         // }
    //     }
    //     printf("\n");
    // }
    //printf("THREAD CHECK PASSED\n");


    // assemble query response
    time = clock();
    int numErasures = r;
    int numResponses = p - numErasures;
    uint8_t* erasureIndexList = (uint8_t*)malloc(p);
    memset(erasureIndexList,0,p);
    for (int i = 0; i < p; i++) {
        erasureIndexList[i] = (i < numErasures) ? 0 : 1;
    }
    //printBuffer(erasureIndexList,p);
    //uint8_t* vandermondeMat = (uint8_t*)malloc(p*(k+1));
    //gen_encode_matrix(vandermondeMat,p,k+1);
    //uint8_t* decodeMat = (uint8_t*)malloc((k+1)*(k+1));
    uint8_t*** testResponses  = (uint8_t***)malloc(numResponses*sizeof(uint8_t**));
    for (int i = 0; i < numResponses; i++) {
        testResponses[i] = (uint8_t**)malloc(NUM_CD_KEYS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_CD_KEYS; j++) {
            testResponses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        }
    }

    int curr = 0;

    for (int i = 0; i < p; i++) {
        if (erasureIndexList[i]!= 0) {
            for (int j = 0 ; j < NUM_CD_KEYS; j++) {
                //printf("BEFORE COPY\n");
                //printBuffer(responses[i][j], ENCODED_FILE_SIZE_BYTES);
                memcpy(testResponses[curr][j],threadResponses[i][j],ENCODED_FILE_SIZE_BYTES);
                //testResponses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
            }
            curr++;
        }
    }
    // for (int i = 0; i < numResponses; i++) {
    //     for (int j = 0; j < NUM_RSS_KEYS; j++) {
    //         printf("PRINTING PARTY %d RESPONSE %d\n", i + 1, j);
    //         printBuffer(testResponses[i][j], ENCODED_FILE_SIZE_BYTES);
    //     }
    // }
    // printf("\n\n\n");
    uint8_t* test = (uint8_t*)malloc(FILE_SIZE_BYTES);
    memset(test,0,FILE_SIZE_BYTES);
    assembleCDResponses(&c, erasureIndexList, testResponses, test);
    time = clock() - time;
    //printf(“%f SECONDS TO DECODE W ONE ERASURE WITH LOG DOMAIN SIZE %d\n”, (float)time/CLOCKS_PER_SEC,logNumFiles);

    printBuffer(test,FILE_SIZE_BYTES);

    for (int i = 0; i < FILE_SIZE_BYTES; i++) {
        assert(test[i] == c.unencoded_files[index][i]);
    }

    free(keys);
    freeParams();
}

void runShamirPirTests(int logNumFiles, int fileSizeBytes, uint128_t index, int k, int t, int r, int b, int rho, int checkMac, int numThreads) {
    clock_t time;
    // int p = (int)ceil((2*t + 2*k + r + (2*b))/2);
    // int p = (int)ceil(double(2*t + 2*k)/2 + r + 2*b);
    //int numFiles = pow(2,logNumFiles);

    //printf("%d\n", p);
    // setSystemParams(logNumFiles, fileSizeBytes, p, t, k, r, b, 0, 2, 0);
    setSystemParams(logNumFiles, fileSizeBytes, t, k, r, b, rho, checkMac, 2);
    int p = NUM_PARTIES; 
    // initialize client
    client c;
    initialize_client(&c,logNumFiles,fileSizeBytes);
    // initialize servers
    server servers[p]; // TODO 
    int currByzantine = 0;
    for (int i = p-1; i >= 0; i--) {
        // printf("%d\n",i);
        int isByzantine = 0;
        if (currByzantine < b) {
            isByzantine = 1;
            currByzantine++;
        }
        initializeServer(&servers[i],i+1,LOG_NUM_ENCODED_FILES,ENCODED_FILE_SIZE_BYTES, isByzantine, numThreads);
        encode_within_files_server(&c, &servers[i]);
        //printServer(&servers[i]);
    }
    

    // prepare keys
    int keyLength = calcShamirDPFKeyLength(LOG_NUM_ENCODED_FILES);
    // //printf(“PARAMS %d %d %d\n”,p,LOG_NUM_ENCODED_FILES,NUM_ROUNDS);
    printf("KEY LENGTH %d\n",keyLength);
    uint8_t*** keys = (uint8_t***)malloc(p*sizeof(uint8_t**));
    for (int j = 0 ; j < p; j++) {
        keys[j] = (uint8_t**)malloc(NUM_ROUNDS*sizeof(uint8_t*));
        for (int i = 0; i < NUM_ROUNDS; i++) {
            keys[j][i] = (uint8_t*)malloc(keyLength);
        }
    }
    // Generate Shamir Coefficients
    int n = LOG_NUM_ENCODED_FILES;
    int x = LOG_NUM_ENCODED_FILES/2 + (LOG_NUM_ENCODED_FILES % 2 != 0);
    int y = n - x;

    uint8_t*** coeffs_x = (uint8_t***)malloc(NUM_ROUNDS*sizeof(uint8_t**));
    uint8_t*** coeffs_y = (uint8_t***)malloc(NUM_ROUNDS*sizeof(uint8_t**));
    for (int i = 0; i < NUM_ROUNDS; i++) {
        coeffs_x[i] = (uint8_t**)malloc((int)pow(2,x)*sizeof(uint8_t*));
        coeffs_y[i] = (uint8_t**)malloc((int)pow(2,y)*sizeof(uint8_t*));
        for (int j = 0; j < (int)pow(2,x); j++) {
            coeffs_x[i][j] = (uint8_t*)malloc(T+NUM_ROUNDS);
            memset(coeffs_x[i][j],0,T+NUM_ROUNDS);
        }
        for (int j = 0; j < (int)pow(2,y); j++) {
            coeffs_y[i][j] = (uint8_t*)malloc(T+NUM_ROUNDS);
            memset(coeffs_y[i][j],0,T+NUM_ROUNDS);
        }
    } 
    time = clock(); 
    genShamirCoeffs(n, T, NUM_ROUNDS, index, coeffs_x, coeffs_y);

    // time = clock(); 
    genOptShamirDPF(LOG_NUM_ENCODED_FILES, index, T, NUM_PARTIES, NUM_ROUNDS, keys, coeffs_x, coeffs_y);
    time = clock() - time;
    printf("%f SECONDS TO GEN SHAMIR DPF WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,LOG_NUM_FILES);

    // for (int j = 0 ; j < p; j++) {
    //     for (int i = 0; i < NUM_ROUNDS; i++) {
    //         printf("PRINTING PARTY %d KEY %d\n", j+1, i+1);
    //         printBuffer(keys[j][i],keyLength);
    //     }
    // }

    int responseLength = calcShamirResponseLength(LOG_NUM_ENCODED_FILES, ENCODED_FILE_SIZE_BYTES); 
    uint8_t*** responses  = (uint8_t***)malloc(p*sizeof(uint8_t**));
    //printf(“Gets Here\n”);
    for (int i = 0; i < p; i++) {
        responses[i] = (uint8_t**)malloc(NUM_ROUNDS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_ROUNDS; j++) {
            responses[i][j] = (uint8_t*)malloc(responseLength);
        }
    }

    uint8_t*** threadResponses  = (uint8_t***)malloc(p*sizeof(uint8_t**));
    //printf(“Gets Here\n”);
    for (int i = 0; i < p; i++) {
        threadResponses[i] = (uint8_t**)malloc(NUM_ROUNDS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_ROUNDS; j++) {
            threadResponses[i][j] = (uint8_t*)malloc(responseLength);
        }
    }

    uint8_t*** perThread  = (uint8_t***)malloc(numThreads*sizeof(uint8_t**));
    //printf(“Gets Here\n”);
    for (int i = 0; i < numThreads; i++) {
        perThread[i] = (uint8_t**)malloc(NUM_ROUNDS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_ROUNDS; j++) {
            perThread[i][j] = (uint8_t*)malloc(responseLength);
        }
    }

    // run queries on each server
    int slice = NUM_ENCODED_FILES / numThreads;
    printf("SIZE OF SLICE IS %d\n", slice);
    for (int i = 0; i < p; i++) {
        //printf("GETS HERE\n");
        time = clock();
        runOptShamirDPFQuery(&servers[i], keys[i], responses[i]);
        time = clock() - time;
        //printf("%f SECONDS TO RUN SHAMIR QUERY OPTIMIZED WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,LOG_NUM_FILES);
        for (int j = 0; j < numThreads; j++) {
            time = clock();
            runOptShamirDPFQueryThread(&servers[i], keys[i], j, j*slice, (j+1)*slice, perThread[j]);
            time = clock() - time;
            printf("%f SECONDS TO RUN SHAMIR QUERY OPTIMIZED THREAD WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,LOG_NUM_FILES);
        }
        assembleShamirQueryThreadResults(&servers[i], perThread, numThreads, threadResponses[i]);
        // if (i == 2) {
        //     printf("PRINTING THREAD CONTENTS\n");
        //     for (int j = 0; j < numThreads; j++) {
        //         for (int k = 0; k < NUM_ROUNDS; k++) {
        //             printBuffer(perThread[j][k],responseLength);
        //         }
        //     }
        // }
        for (int j = 0; j < numThreads ; j++) {
            for (int k = 0; k < NUM_ROUNDS ; k++) {
                memset(perThread[j][k],0,responseLength);
            }
        }
    }
    
    // check threading
    //for (int i =0; i < p; i++) {
    //    for (int j = 0; j < NUM_ROUNDS; j++) {
    //        for (int k = 0; k < responseLength; k++) {
    //            assert(responses[i][j][k] == threadResponses[i][j][k]);
    //        }
    //    }
    //}
    //printf("THREAD CHECK PASSED\n");

    //printf("PARTY %d ROUND %d\n",1,0);
    //printBuffer(responses[0][0], responseLength);


    // assemble query response
    time = clock();
    int numErasures = r;
    int numResponses = p - numErasures;
    uint8_t* erasureIndexList = (uint8_t*)malloc(p);
    for (int i = 0; i < p; i++) {
        erasureIndexList[i] = (i < numErasures) ? 0 : 1;
    }
    //printBuffer(erasureIndexList,p);
    //uint8_t* vandermondeMat = (uint8_t*)malloc(p*(k+1));
    //gen_encode_matrix(vandermondeMat,p,k+1);
    //uint8_t* decodeMat = (uint8_t*)malloc((k+1)*(k+1));
    uint8_t*** testResponses  = (uint8_t***)malloc(numResponses*sizeof(uint8_t**));
    for (int i = 0; i < numResponses; i++) {
        testResponses[i] = (uint8_t**)malloc(NUM_ROUNDS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_ROUNDS; j++) {
            testResponses[i][j] = (uint8_t*)malloc(responseLength);
        }
    }

    int curr = 0;
    for (int i = 0; i < p; i++) {
        if (erasureIndexList[i]!= 0) {
            for (int j = 0 ; j < NUM_ROUNDS; j++) {
                memcpy(testResponses[curr][j],responses[i][j],responseLength);
                //testResponses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
            }
            curr++;
        }
    }
    // for (int i = 0; i < numResponses; i++) {
    //     for (int j = 0; j < NUM_RSS_KEYS; j++) {
    //         printf("PRINTING PARTY %d RESPONSE %d\n", i + 1, j);
    //         printBuffer(testResponses[i][j], ENCODED_FILE_SIZE_BYTES);
    //     }
    // }
    // printf("\n\n\n");
    uint8_t* test = (uint8_t*)malloc(FILE_SIZE_BYTES);
    memset(test,0,FILE_SIZE_BYTES);
    assembleShamirResponses(&c, erasureIndexList, testResponses, test, coeffs_x, coeffs_y);
    time = clock() - time;
    //printf(“%f SECONDS TO DECODE W ONE ERASURE WITH LOG DOMAIN SIZE %d\n”, (float)time/CLOCKS_PER_SEC,logNumFiles);

    printBuffer(test,FILE_SIZE_BYTES);

    for (int i = 0; i < FILE_SIZE_BYTES; i++) {
        assert(test[i] == c.unencoded_files[index][i]);
    }

    free(keys);
    freeParams();
}

void runHollantiCorrectnessTests(int logNumFiles, int fileSizeBytes, uint128_t index, int k, int t, int r, int b, int rho, int checkMac, int numThreads) { 
    clock_t time; 
    // int p = k + t + r + (2*b) + 1; 
    int numFiles = pow(2,logNumFiles);
    // setSystemParams(logNumFiles, fileSizeBytes, p, t, k, r, b, 0, 0, 0);
    setSystemParams(logNumFiles, fileSizeBytes, t, k, r, b, rho, checkMac, 3);
    int p = NUM_PARTIES; 
    // initialize client
    client c;
    initialize_client(&c,logNumFiles,fileSizeBytes);

    // initialize servers 
    server servers[p];
    int currByzantine = 0;
    for (int i = p-1; i >= 0; i--) {
        int isByzantine = 0;
        if (currByzantine < b) {
            isByzantine = 1;
            currByzantine++;
        }
        //printf("IS BYZANTINE %d\n",isByzantine);
        initializeServer(&servers[i],i+1,LOG_NUM_ENCODED_FILES,ENCODED_FILE_SIZE_BYTES, isByzantine, numThreads);
        encode_within_files_server(&c, &servers[i]);
        //printServer(&servers[i]);
    }

    // prepare keys 
    int keyLength = NUM_FILES;
    //printf("PARAMS %d %d %d\n",p,LOG_NUM_ENCODED_FILES,NUM_ROUNDS);
    printf("KEY LENGTH %d\n",keyLength);
    uint8_t*** keys = (uint8_t***)malloc(p*sizeof(uint8_t**));
    for (int i = 0 ; i < p; i++) {
        keys[i] = (uint8_t**)malloc(NUM_ROUNDS * sizeof(uint8_t*));
        for (int j = 0; j < NUM_ROUNDS; j++) {
            keys[i][j] = (uint8_t*)malloc(keyLength);
        }
    }

    time = clock();
    // void genHollantiQuery(int log_domainSize, uint128_t index, int t, int p, int numRounds, uint8_t*** key_output);
    generateHollantiQuery(&c, index, keys);
    time = clock() - time; 
    printf("%f SECONDS TO GEN HOLLANTI QUERY WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,LOG_NUM_FILES);

    uint8_t*** responses  = (uint8_t***)malloc(p*sizeof(uint8_t**));
    //printf("Gets Here\n");
    for (int i = 0; i < p; i++) {
        responses[i] = (uint8_t**)malloc(NUM_ROUNDS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_ROUNDS; j++) {
            responses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        }
    }
    // run queries on each server 
    for (int i = 0; i < p; i++) {
        time = clock();
        runHollantiQuery(&servers[i], keys[i], responses[i]);
        time = clock() - time; 
        printf("%f SECONDS TO RUN HOLLANTI QUERY OPTIMIZED WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,LOG_NUM_FILES);
    }

    // assemble query response 
    time = clock();
    int numErasures = r; 
    int numResponses = p - numErasures; 

    int erasedIndex = 0; //chosen randomly 
    uint8_t* erasureIndexList = (uint8_t*)malloc(p);
    for (int i = 0; i < p; i++) {
        erasureIndexList[i] = (i < numErasures) ? 0 : 1;
    }
    //printBuffer(erasureIndexList,p);
    uint8_t* vandermondeMat = (uint8_t*)malloc(p*(k+1));
    gen_encode_matrix(vandermondeMat,p,k+1);
    uint8_t* decodeMat = (uint8_t*)malloc((k+1)*(k+1));
    uint8_t*** testResponses  = (uint8_t***)malloc(numResponses*sizeof(uint8_t**));
    for (int i = 0; i < numResponses; i++) {
        testResponses[i] = (uint8_t**)malloc(NUM_ROUNDS*sizeof(uint8_t*));
        for (int j = 0 ; j < NUM_ROUNDS; j++) {
            testResponses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        }
    }

    int curr = 0;
    for (int i = 0; i < p; i++) {
        if (erasureIndexList[i]!= 0) {
            for (int j = 0 ; j < NUM_ROUNDS; j++) {
                memcpy(testResponses[curr][j],responses[i][j],ENCODED_FILE_SIZE_BYTES);
                //testResponses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
            }
            curr++;
        }
    }

    uint8_t* test = (uint8_t*)malloc(FILE_SIZE_BYTES);
    assembleHollantiResponses(&c, erasureIndexList, testResponses, test); 
    time = clock() - time; 
    //printf("%f SECONDS TO DECODE W ONE ERASURE WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,logNumFiles);
    printBuffer(test,FILE_SIZE_BYTES);
    for (int i = 0; i < FILE_SIZE_BYTES; i++) {
        assert(test[i] == c.unencoded_files[index][i]);
    }

    free(vandermondeMat);
    free(decodeMat);
    free(erasureIndexList);
    free(test);
    free_client(&c);
    for (int i = 0; i < p; i++) {
        freeServer(&servers[i]);
    }
    // for (int i = 0; i < p; i++) {
    //     for (int j = 0; j < NUM_ROUNDS; j++) {
    //         free(keys[i][j]);
    //     }
    //     free(keys[i]);
    // }
    // free(keys);
    for (int i = 0; i < p; i++) {
        for (int j = 0 ; j < NUM_ROUNDS; j++) {
            free(responses[i][j]);
        }
        free(responses[i]);
    }
    free(responses);
    for (int i = 0; i < numResponses; i++) {
        for (int j = 0 ; j < NUM_ROUNDS; j++) {
            free(testResponses[i][j]);
        }
        free(testResponses[i]);
    }
    free(testResponses);
}

void runWoodruffCorrectnessTests(int logNumFiles, int fileSizeBytes, uint128_t index, int k, int t, int r, int b, int rho, int checkMac, int numThreads) {
    clock_t time; 
    //int p = int(ceil((double(2*t + 1)/2))) + r + 2*b; 
    // int p = 2*t + 1 + r + 2*b; 
    // int p = 4;

    //printf("NUMBER OF PARTIES: %d\n", p);
    int numFiles = pow(2,logNumFiles);
    //setSystemParams(logNumFiles, fileSizeBytes, p, t, k, r, b, 0, 0, 0);
    setSystemParams(logNumFiles, fileSizeBytes, t, k, r, b, rho, checkMac, 5);
    int p = NUM_PARTIES; 
    client c;
    initialize_client(&c,logNumFiles,fileSizeBytes);
    // printf("KEY LENGTH %d\n",2);
    // initialize servers 
    server servers[NUM_PARTIES];
    int currByzantine = 0;
    for (int i = p-1; i >= 0; i--) {
        int isByzantine = 0;
        if (currByzantine < b) {
            isByzantine = 1;
            currByzantine++;
        }
        //printf("IS BYZANTINE %d\n",isByzantine);
        initializeServer(&servers[i],i+1,LOG_NUM_ENCODED_FILES,ENCODED_FILE_SIZE_BYTES, isByzantine, numThreads);
        encode_within_files_server(&c, &servers[i]);
        // printServer(&servers[i]);
    }

    int keyLength = calcWoodruffKeyLength(p,b,t,logNumFiles,fileSizeBytes);
    //printf("PARAMS %d %d %d\n",p,LOG_NUM_ENCODED_FILES,NUM_ROUNDS);

    printf("KEY LENGTH %d\n",keyLength);
    uint8_t** keys = (uint8_t**)malloc(p*sizeof(uint8_t*));
    for (int i = 0 ; i < p; i++) {
        keys[i] = (uint8_t*)malloc(keyLength);
    }

    time = clock();
    // void genHollantiQuery(int log_domainSize, uint128_t index, int t, int p, int numRounds, uint8_t*** key_output);
    uint8_t** v = (uint8_t**)malloc(t*sizeof(uint8_t*));
    for (int i = 0; i < t; i++) {
        v[i] = (uint8_t*)malloc(WOODRUFF_M);
    }

    genWoodruffVs(t,WOODRUFF_M,v);

    // TODO: Ensure that indexes other than one can be used
    genWoodruffQuery(index, t, p, WOODRUFF_M, v, keys);

    // for (int i = 0 ; i < p; i++) {
    //     printBuffer(keys[i],keyLength);
    // }

    // generateWoodruffQuery(&c, index, keys);
    time = clock() - time; 
    printf("%f SECONDS TO GEN Woodruff QUERY WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,LOG_NUM_FILES);

    uint8_t*** threadResponses  = (uint8_t***)malloc(p*sizeof(uint8_t**));
    uint8_t*** mac_threadResponses  = (uint8_t***)malloc(p*sizeof(uint8_t**));
    //printf(“Gets Here\n”);
    for (int i = 0; i < p; i++) {
        threadResponses[i] = (uint8_t**)malloc((WOODRUFF_M+1)*sizeof(uint8_t*));
        mac_threadResponses[i] = (uint8_t**)malloc((WOODRUFF_M+1)*sizeof(uint8_t*));
        for (int j = 0 ; j < (WOODRUFF_M+1); j++) {
            threadResponses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
            mac_threadResponses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        }
    }

    uint8_t*** perThread  = (uint8_t***)malloc(numThreads*sizeof(uint8_t**));
    uint8_t*** mac_perThread  = (uint8_t***)malloc(numThreads*sizeof(uint8_t**));
    //printf(“Gets Here\n”);
    for (int i = 0; i < numThreads; i++) {
        perThread[i] = (uint8_t**)malloc((WOODRUFF_M+1)*sizeof(uint8_t*));
        mac_perThread[i] = (uint8_t**)malloc((WOODRUFF_M+1)*sizeof(uint8_t*));
        for (int j = 0 ; j < (WOODRUFF_M+1); j++) {
            perThread[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
            mac_perThread[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
        }
    }

    // run queries on each server
    int slice = NUM_ENCODED_FILES / numThreads;
    for (int i = 0; i < p; i++) {
        //printf("%f SECONDS TO RUN SHAMIR QUERY OPTIMIZED WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,LOG_NUM_FILES);
        for (int j = 0; j < numThreads; j++) {
            time = clock();
            // runOptShamirDPFQueryThread(&servers[i], keys[i], j, j*slice, (j+1)*slice, perThread[j]);
            runWoodruffQueryThread(&servers[i], keys[i], j, j*slice, (j+1)*slice, perThread[j]);
            time = clock() - time;
            printf("%f SECONDS TO RUN WOODRUFF QUERY OPTIMIZED THREAD WITH LOG DOMAIN SIZE %d\n", (float)time/CLOCKS_PER_SEC,LOG_NUM_FILES);
        }
        assembleWoodruffQueryThreadResults(&servers[i], perThread, numThreads, threadResponses[i]);
        assembleWoodruffQueryThreadResults(&servers[i], mac_perThread, numThreads, mac_threadResponses[i]);
        // printf("SIZE OF SLICE IS %d\n", slice);
        for (int j = 0; j < numThreads ; j++) {
            for (int k = 0; k < WOODRUFF_M + 1 ; k++) {
                memset(perThread[j][k],0, ENCODED_FILE_SIZE_BYTES);
                memset(mac_perThread[j][k],0, ENCODED_FILE_SIZE_BYTES);
            }
        }
        // printf("SIZE2 OF SLICE IS %d\n", slice);
    }

    // printBuffer(threadResponses[0][0],ENCODED_FILE_SIZE_BYTES);
    // printBuffer(threadResponses[1][0],ENCODED_FILE_SIZE_BYTES);

    time = clock();
    int numErasures = r;
    int numResponses = p - numErasures;

    uint8_t* erasureIndexList = (uint8_t*)malloc(p);
    for (int i = 0; i < p; i++) {
        erasureIndexList[i] = (i < numErasures) ? 0 : 1;
    }

    //printBuffer(erasureIndexList,p);
    //uint8_t* vandermondeMat = (uint8_t*)malloc(p*(k+1));
    //gen_encode_matrix(vandermondeMat,p,k+1);
    //uint8_t* decodeMat = (uint8_t*)malloc((k+1)*(k+1));
    uint8_t*** testResponses  = (uint8_t***)malloc(numResponses*sizeof(uint8_t**));
    uint8_t*** mac_testResponses  = (uint8_t***)malloc(numResponses*sizeof(uint8_t**));
    for (int i = 0; i < numResponses; i++) {
        testResponses[i] = (uint8_t**)malloc((WOODRUFF_M+1)*sizeof(uint8_t*));
        mac_testResponses[i] = (uint8_t**)malloc((WOODRUFF_M+1)*sizeof(uint8_t*));
        for (int j = 0 ; j < (WOODRUFF_M+1); j++) {
            testResponses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
            mac_testResponses[i][j] = (uint8_t*)malloc((WOODRUFF_M+1)*sizeof(uint8_t*));
        }
    }

    int curr = 0;
    for (int i = 0; i < p; i++) {
        if (erasureIndexList[i]!= 0) {
            for (int j = 0 ; j < (WOODRUFF_M+1); j++) {
                memcpy(testResponses[curr][j],threadResponses[i][j],ENCODED_FILE_SIZE_BYTES);
                memcpy(mac_testResponses[curr][0],mac_threadResponses[i][0],ENCODED_FILE_SIZE_BYTES);
                //testResponses[i][j] = (uint8_t*)malloc(ENCODED_FILE_SIZE_BYTES);
            }
            curr++;
        }
    }

    //printf("PRINTING DERIVATIVES\n");
    // for (int i = 0; i < WOODRUFF_M+1; i++) {
    //     printBuffer(testResponses[2][i],ENCODED_FILE_SIZE_BYTES);
    // }
    // printBuffer(testResponses[0][0],ENCODED_FILE_SIZE_BYTES);
    // printBuffer(testResponses[1][0],ENCODED_FILE_SIZE_BYTES);
    // printBuffer(testResponses[2][0],ENCODED_FILE_SIZE_BYTES);

    // for (int i = 0; i < numResponses; i++) {
    //     for (int j = 0; j < NUM_RSS_KEYS; j++) {
    //         printf("PRINTING PARTY %d RESPONSE %d\n", i + 1, j);
    //         printBuffer(testResponses[i][j], ENCODED_FILE_SIZE_BYTES);
    //     }
    // }
    // printf("\n\n\n");
    uint8_t* test = (uint8_t*)malloc(FILE_SIZE_BYTES);
    memset(test,0,FILE_SIZE_BYTES);
    assembleWoodruffResponses(&c, erasureIndexList, testResponses, test, v);

    // time = clock() - time;
    //printf(“%f SECONDS TO DECODE W ONE ERASURE WITH LOG DOMAIN SIZE %d\n”, (float)time/CLOCKS_PER_SEC,logNumFiles);

    printBuffer(test,FILE_SIZE_BYTES);
    //printBuffer(mac_test,FILE_SIZE_BYTES);

    for (int i = 0; i < FILE_SIZE_BYTES; i++) {
        assert(test[i] == c.unencoded_files[index][i]);
    }

    


}

/*
int main() {
    int logNumFiles = 15; 
    int fileSizeBytes = 8; 
    int index = 1;
    int k = 2; 
    int t = 2;
    int r = 0;
    int b = 1; 
    int numThreads = 1; 
    int rho = 1;
    int checkMac = 0;

    //printf("CLIENT WITH OPTIMIZATION\n");
    // runClientDPFTreeOptCorrectnessTests(logNumFiles, fileSizeBytes, index, k, r, b, rho, checkMac, numThreads);
    //printf("Client Correctness Tests Passed!\n");
    // runClientMultiPartyPirTests(logNumFiles, fileSizeBytes, index, k, t, r, 0, rho, checkMac,  numThreads);
    // runClientMultiPartyPirTests(logNumFiles, fileSizeBytes, index, k, t, r, 1, rho, checkMac,  numThreads);
    runCDPirTests(logNumFiles, fileSizeBytes, index, k, t, r, b, rho, checkMac, numThreads);
    // runShamirPirTests(logNumFiles, fileSizeBytes, index, k, t, r, b, rho, checkMac, numThreads);
    // runShamirPirTests(logNumFiles, fileSizeBytes, index, k, t, r, b, rho, checkMac, 1);
    // runHollantiCorrectnessTests(logNumFiles, fileSizeBytes, index, k, t, r, 0, rho, checkMac, numThreads);
    // runHollantiCorrectnessTests(logNumFiles, fileSizeBytes, index, 1, t, r, 2, rho, checkMac, numThreads);
    // runWoodruffCorrectnessTests(logNumFiles,fileSizeBytes,index,k,t,r,0, rho, checkMac, numThreads);
    // runWoodruffCorrectnessTests(logNumFiles,fileSizeBytes,index,1,t,r,b, rho, checkMac, numThreads);
    // printf("%d\n",calcOptimizedDPFTreeKeyLength(6, 20, 1));
    // printf("%d\n",calcOptimizedDPFTreeKeyLength(12,25, 1));
    // printf("%d\n",calcShamirDPFKeyLength(25));
    //printf("%d\n",calcShamirDPFKeyLength(22));
    //printf("%d\n",calcCDDPFKeyLength(8, 20, 2, 6, 3));
    // printf("%d\n",calcCDDPFKeyLength(8, 20, 2, 6, 3));
    // printf("%d\n",calcCDDPFKeyLength(16, 25, 2, 6, 3));
    // printf("%d\n",calcWoodruffKeyLength(9, 0, 2, 25, 128));
    printf("%d\n",calcShamirResponseLength(22, 128));
    printf("%d\n",calcShamirResponseLength(25, 32));
    // printf("%d\n",calcShamirResponseLength(25, 128));
    // setSystemParams(10, 8, 2, 1, 0, 1, 1, 0, 3);
    return 0;
}
*/
