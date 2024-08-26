#ifndef _CLIENT_H
#define _CLIENT_H

#include "common.h"
#include "params.h"
#include "server.h"

#include <openssl/evp.h>
#include <openssl/bn.h>

#ifndef SWIG
    typedef unsigned __int128 uint128_t;
#endif

typedef struct {
    EVP_CIPHER_CTX *ctx;
    const EVP_MD *macCtx;
    uint8_t** unencoded_files;
    uint8_t* macKey;
} client;

void initialize_client(client *c, uint8_t log_num_files, uint32_t file_size_bytes);
void free_client(client *c);

void generate_encoded_within_file(client* c, int party_index, int file_index, uint8_t* encoded_file);
void generate_encoded_across_file(client* c, int party_index, int file_index, uint8_t* encoded_file);

void encode_across_files_server(client* c, server* s);
void encode_within_files_server(client* c, server* s);

void generate_DPF_tree_query(client *c, int index, uint8_t*** keys);
void generate_opt_DPF_tree_query(client *c, int index, uint8_t*** keys);
void assembleDPFTreeQueryResponses(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output);
//void assembleDPFTreeQueryResponsesMalicious(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output);

void generateMultiPartyDPFQuery(client *c, int index, uint8_t*** keys);

void assembleMultiPartyResponses(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output);
//void assembleMultiPartyResponsesMalicious(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output);

void generateShamirDPFQuery(client *c, int index, uint8_t*** keys);
void assembleShamirResponses(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output, uint8_t*** coeffs_x, uint8_t*** coeffs_y);
//void assembleShamirResponsesMalicious(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output, uint8_t*** coeffs_x, uint8_t*** coeffs_y);

void generateHollantiQuery(client *c, int index, uint8_t*** keys);
void assembleHollantiResponses(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output);
//void assembleHollantiResponsesMalicious(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output);

void generateCDQuery(client *c, int index, uint8_t*** keys);
void assembleCDResponses(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output);
//void assembleCDResponsesMalicious(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output);

int checkMac(client* c, uint8_t* finalResult, uint8_t* mac, int across);

void generateWoodruffQuery(client *c, int index, uint8_t*** keys);
void assembleWoodruffResponses(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output, uint8_t** v);
//void assembleWoodruffResponsesMalicious(client *c, uint8_t* erasureIndexList, uint8_t*** responses, uint8_t* output, uint8_t** v);

#endif