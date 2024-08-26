#ifndef _CODING_H
#define _CODING_H

#include <iostream>
#include <cassert>
#include <cstring>
#include <math.h>   
#include "ec_base.h"

unsigned char gf_mul(unsigned char a, unsigned char b);
unsigned char gf_inv(unsigned char a);
unsigned char gf_pow(unsigned char base, unsigned char exp);
void gen_encode_matrix(uint8_t* encode_matrix, int n, int k);
int gf_invert_matrix(uint8_t* in_mat, uint8_t* out_mat, const int n);
void gen_decode_matrix(uint8_t* encodeMatrix, uint8_t* decodeMatrix, uint8_t* erasureIndexList, int k, int n);

uint8_t computeDecoding(uint8_t* decodeMat, uint8_t* shares, int numShares, int index);
uint8_t computeInvTimesResponse(uint8_t* decodeMat, uint8_t* shares, int numShares, int index);
uint8_t computeDecodingMalicious(uint8_t* decodeMat, uint8_t* outputVals, int numShares, int gInd);
uint8_t computeMultiPartyDecodingMalicious(uint8_t* responseIndices, uint8_t* shares, int numResponses, int k, int b);
uint8_t computeShamirDecodingMalicious(uint8_t* responseIndices, uint8_t* shares, int numResponses, int deg, int b);
#endif