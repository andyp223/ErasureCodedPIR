#ifndef _SERVER_H
#define _SERVER_H

#include "common.h"
#include "params.h"
#include <openssl/evp.h>
#include <openssl/bn.h>

#ifndef SWIG
    typedef unsigned __int128 uint128_t;
#endif

typedef struct {
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER_CTX **ctxThreads;
    //int num_parties;
    int partyIndex;
    uint8_t **indexList;

    //uint32_t numFiles;
    //uint32_t logNumFiles;
    //uint32_t fileSize;
    int isByzantine;
    int numThreads;
} server;

void initializeServer(server *s, int partyIndex, uint32_t logNumFiles, uint32_t fileSizeBytes, int isByzantine, int numThreads); 
void freeServer(server *s);
void printServer(server *s);

void runSingleDPFTreeQuery(server *s, uint8_t* key, uint8_t** result);
void runDPFTreeQuery(server *s, uint8_t** keys, int numKeys, uint8_t** result);
void runOptimizedDPFTreeQuery(server *s, uint8_t* key, int numQueries, uint8_t** result);

void runSingleMultiPartyDPFQuery(server *s, uint8_t* key, uint8_t** result);
void runMultiPartyDPFQuery(server *s, uint8_t** keys, int numKeys, uint8_t** result);
void runOptimizedMultiPartyDPFQuery(server *s, uint8_t* key, uint8_t** result);
void runOptShamirDPFQuery(server *s, uint8_t** keys, uint8_t** result);
void runHollantiQuery(server *s, uint8_t** key, uint8_t** result);

int get2pow(int pow);

void runOptShamirDPFQueryThread(server *s, uint8_t** keys, int threadNum, int startIndex, int endIndex, uint8_t** result);
void runHollantiQueryThread(server *s, uint8_t** keys, int threadNum, int startIndex, int endIndex, uint8_t** result);
void runWoodruffQueryThread(server *s, uint8_t* key, int threadNum, int startIndex, int endIndex, uint8_t** result);
void runOptimizedMultiPartyDPFQueryThread(server *s, uint8_t* key, int threadNum, int numThreads, uint8_t** result); 
void runCDQueryThread(server *s, uint8_t* key, int threadNum, int numThreads, uint8_t** result); 
void runOptimizedDPFTreeQueryThread(server *s, uint8_t* key, int threadNum, int numThreads, uint8_t** result);

void assembleShamirQueryThreadResults(server *s, uint8_t ***in, int numThreads, uint8_t **out);
void assembleHollantiQueryThreadResults(server *s, uint8_t ***in, int numThreads, uint8_t **out);
void assembleMultipartyDPFQueryThreadResults(server *s, uint8_t ***in, int numThreads, uint8_t **out);
void assemblDPFTreeQueryThreadResults(server *s, uint8_t ***in, int numThreads, uint8_t **out);
void assembleCDQueryThreadResults(server *s, uint8_t ***in, int numThreads, uint8_t **out);
void assembleWoodruffQueryThreadResults(server *s, uint8_t ***in, int numThreads, uint8_t **out);


#endif