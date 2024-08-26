#include <iostream>
#include <cassert>
#include <cstring>
#include <math.h>   
#include "ec_base.h"
#include "utils.h"

// copied from isa-l
unsigned char gf_mul(unsigned char a, unsigned char b)
{
#ifndef GF_LARGE_TABLES
	int i;

	if ((a == 0) || (b == 0))
		return 0;

	return gff_base[(i = gflog_base[a] + gflog_base[b]) > 254 ? i - 255 : i];
#else
	return gf_mul_table_base[b * 256 + a];
#endif
}

// copied from isa-l
unsigned char gf_inv(unsigned char a)
{
#ifndef GF_LARGE_TABLES
	if (a == 0)
		return 0;

	return gff_base[255 - gflog_base[a]];
#else
	return gf_inv_table_basse[a];
#endif
}

static const unsigned char gf_pow_table[] = {
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1d,0x3a,0x74,
	0x01,0x03,0x05,0x0f,0x11,0x33,0x55,0xff,0x1c,0x24,0x6c,
	0x01,0x04,0x10,0x40,0x1d,0x74,0xcd,0x13,0x4c,0x2d,0xb4,
	0x01,0x05,0x11,0x55,0x1c,0x6c,0xc1,0xe2,0x4d,0x64,0xe9,
	0x01,0x06,0x14,0x78,0x0d,0x2e,0xe4,0x62,0x51,0xfb,0x20
};

unsigned char gf_pow(unsigned char base, unsigned char exp) {
	unsigned char output = 1;
	int i;
	while (exp > 0) {
		if (exp & 1 == 1) // y is odd
		{
			//output = gf_mul(output,base);
		
			output = gff_base[(i = gflog_base[output] + gflog_base[base]) > 254 ? i - 255 : i];
		}
		base = gff_base[(i = 2*gflog_base[base]) > 254 ? i - 255 : i];
		exp = exp >> 1; // y=y/2;
	}
	return output;
}


// generates k by n Vandermonde encoding matrix for MDS code
void gen_encode_matrix(uint8_t* encode_matrix, int n, int k) {
    for (int i = 0; i < k; i++) {
        for (int j = 0; j < n; j++) {
            encode_matrix[i*n + j] = gf_pow(j+1,i);  
        }
    }	
}

// copied from isa-l 
int gf_invert_matrix(uint8_t* in_mat, uint8_t* out_mat, const int n)
{
	int i, j, k;
	unsigned char temp;

	// Set out_mat[] to the identity matrix
	for (i = 0; i < n * n; i++)	// memset(out_mat, 0, n*n)
		out_mat[i] = 0;

	for (i = 0; i < n; i++)
		out_mat[i * n + i] = 1;

	// Inverse
	for (i = 0; i < n; i++) {
		// Check for 0 in pivot element
		if (in_mat[i * n + i] == 0) {
			// Find a row with non-zero in current column and swap
			for (j = i + 1; j < n; j++)
				if (in_mat[j * n + i])
					break;

			if (j == n)	// Couldn't find means it's singular
				return -1;

			for (k = 0; k < n; k++) {	// Swap rows i,j
				temp = in_mat[i * n + k];
				in_mat[i * n + k] = in_mat[j * n + k];
				in_mat[j * n + k] = temp;

				temp = out_mat[i * n + k];
				out_mat[i * n + k] = out_mat[j * n + k];
				out_mat[j * n + k] = temp;
			}
		}

		temp = gf_inv(in_mat[i * n + i]);	// 1/pivot
		for (j = 0; j < n; j++) {	// Scale row i by 1/pivot
			in_mat[i * n + j] = gf_mul(in_mat[i * n + j], temp);
			out_mat[i * n + j] = gf_mul(out_mat[i * n + j], temp);
		}

		for (j = 0; j < n; j++) {
			if (j == i)
				continue;

			temp = in_mat[j * n + i];
			for (k = 0; k < n; k++) {
				out_mat[j * n + k] ^= gf_mul(temp, out_mat[i * n + k]);
				in_mat[j * n + k] ^= gf_mul(temp, in_mat[i * n + k]);
			}
		}
	}
	return 0;
}



void gen_decode_matrix(uint8_t* encodeMatrix, uint8_t* decodeMatrix, uint8_t* erasureIndexList, int k, int n) {
	uint8_t* b = (uint8_t*)malloc(k*k);
	int currCol = 0; 
	for (int i = 0; i < n; i++) {
		if (erasureIndexList[i] == 1) {
			// copy i'th column into currCol
			for (int j = 0; j < k; j++) {
				b[k * j + currCol] = encodeMatrix[n * j + i];
			}
			currCol++;
		}
	}
	gf_invert_matrix(b, decodeMatrix, k);
	free(b);
}

uint8_t computeDecoding(uint8_t* decodeMat, uint8_t* shares, int numShares, int index) {
	uint8_t output = 0;
	for (int i = 0; i < numShares; i++) {
		output ^= gf_mul(shares[i], decodeMat[i*numShares + index]);
	}
	return output;
}

uint8_t computeInvTimesResponse(uint8_t* decodeMat, uint8_t* shares, int numShares, int index) {
	//printBuffer(decodeMat,numShares*numShares);
	uint8_t output = 0;
	for (int i = 0; i < numShares; i++) {
		output ^= gf_mul(shares[i], decodeMat[index*numShares + i]);
	}
	return output;
}


uint8_t computeDecodingMalicious(uint8_t* decodeMat, uint8_t* outputVals, int numShares, int gInd) {
	uint8_t gOutput = 0; 
	uint8_t* invertMat = (uint8_t*)malloc(numShares*numShares);
	gf_invert_matrix(decodeMat,invertMat,numShares);
	for (int i = 0; i < numShares; i++) {
		gOutput ^= gf_mul(outputVals[i],invertMat[gInd*numShares + i]);
	}
	free(invertMat);
	return gOutput;
	//return 1;
}

uint8_t computeMultiPartyDecodingMalicious(uint8_t* responseIndices, uint8_t* shares, int numResponses, int k, int b) {
	int curr_b = 0;
	int gOutput0 = 0;
	int gOutput1 = 0;
	while (curr_b <= b) {
		gOutput0 = 0;
		gOutput1 = 0;
		int numShares = k + 2*curr_b; 
		uint8_t* decodeMat = (uint8_t*)malloc(numShares*numShares);
		uint8_t* decodeMat2 = (uint8_t*)malloc(numShares*numShares);
		uint8_t* invertMat = (uint8_t*)malloc(numShares*numShares);
		uint8_t* invertMat2 = (uint8_t*)malloc(numShares*numShares);
		uint8_t* outputVals = (uint8_t*)malloc(numShares);
		uint8_t* outputVals2 = (uint8_t*)malloc(numShares);
		for (int i = 0; i < numShares; i++) {
			int ind = numResponses - i - 1; 
			for (int x = 0; x < k + curr_b; x++) {
				decodeMat[i*numShares + x] = gf_pow(responseIndices[i],x);
				decodeMat2[i*numShares + x] = gf_pow(responseIndices[ind],x);
			}
			for (int y = 0; y < curr_b; y++) {
				decodeMat[i*numShares + k + curr_b + y] = shares[i];
				decodeMat2[i*numShares + k + curr_b + y] = shares[ind];
			}
			outputVals[i] = gf_mul(shares[i],gf_pow(responseIndices[i],curr_b));
			outputVals2[i] = gf_mul(shares[ind],gf_pow(responseIndices[ind],curr_b));
		}

		gf_invert_matrix(decodeMat,invertMat,numShares);
		gf_invert_matrix(decodeMat2,invertMat2,numShares);

		for (int i = 0; i < numShares; i++) {
			gOutput0 ^= gf_mul(outputVals[i],invertMat[i]);
			gOutput1 ^= gf_mul(outputVals2[i],invertMat2[i]);
		}

		int eOutput = 0;
		if (curr_b > 0) { 
			for (int i = 0; i < numShares; i++) {
				eOutput ^= gf_mul(outputVals[i], invertMat[(k + 1)*numShares + i]);
			}
		}

		free(decodeMat);
		free(decodeMat2);
		free(invertMat);
		free(invertMat2);
		free(outputVals);
		free(outputVals2);

		if (gOutput0 == gOutput1) {
			if (curr_b == 0) {
				return gOutput0;
			} else {
				return gf_mul(gf_inv(eOutput), gOutput0);
			}
		}
		curr_b++; 
	}
	return 0;
	printf("THIS SHOULDNT PRINT\n");
}

uint8_t computeShamirDecodingMalicious(uint8_t* responseIndices, uint8_t* shares, int numResponses, int deg, int b) {
	int curr_b = 0;
	int gOutput0 = 0;
	int gOutput1 = 0;
	while (curr_b <= b) {
		gOutput0 = 0;
		gOutput1 = 0;
		int numShares = deg + 4*curr_b; 
		//uint8_t* encodeMat = (uint8_t*)malloc(numShares*numShares);
		uint8_t* decodeMat = (uint8_t*)malloc(numShares*numShares);
		uint8_t* decodeMat2 = (uint8_t*)malloc(numShares*numShares);
		uint8_t* invertMat = (uint8_t*)malloc(numShares*numShares);
		uint8_t* invertMat2 = (uint8_t*)malloc(numShares*numShares);
		uint8_t* outputVals = (uint8_t*)malloc(numShares);
		uint8_t* outputVals2 = (uint8_t*)malloc(numShares);
		for (int i = 0; i < numShares; i++) {
			int ind = numResponses - i - 1; 
			int partyInd = i/2; 
			int partyInd2 = ind/2; 
			int isDerivative = i % 2;
			int isDerivative2 = ind % 2;
			if (isDerivative) {
                decodeMat[i*numShares] = 0;
                for (int j = 1; j < deg + 2*curr_b; j++) {
                    decodeMat[i*(numShares) + j] = gf_mul((j%2),gf_pow(responseIndices[partyInd], j-1));
                }
            }else {
               	for (int j = 0; j < deg + 2*curr_b; j++) {
                    decodeMat[i*(numShares) + j] = gf_pow(responseIndices[partyInd], j);
                }
            }
			if (isDerivative2) {
                decodeMat2[i*numShares] = 0;
                for (int j = 1; j < deg + 2*curr_b; j++) {
                    decodeMat2[i*(numShares) + j] = gf_mul((j%2),gf_pow(responseIndices[partyInd2], j-1));
                }
            }else {
               	for (int j = 0; j < deg + 2*curr_b; j++) {
                    decodeMat2[i*(numShares) + j] = gf_pow(responseIndices[partyInd2], j);
                }
            }
			for (int y = 0; y < 2*curr_b; y++) {
				decodeMat[i*numShares + deg + 2*curr_b + y] = gf_mul(shares[i], gf_pow(responseIndices[partyInd],y));
				decodeMat2[i*numShares + deg + 2*curr_b + y] = gf_mul(shares[ind], gf_pow(responseIndices[ind],y));
			}
			outputVals[i] = gf_mul(shares[i],gf_pow(responseIndices[partyInd],2*curr_b));
			outputVals2[i] = gf_mul(shares[ind],gf_pow(responseIndices[partyInd2],2*curr_b));
		}

		gf_invert_matrix(decodeMat,invertMat,numShares);
		gf_invert_matrix(decodeMat2,invertMat2,numShares);

		for (int i = 0; i < numShares; i++) {
			gOutput0 ^= gf_mul(outputVals[i],invertMat[(deg - 1)*numShares + i]);
			gOutput1 ^= gf_mul(outputVals2[i],invertMat2[(deg - 1)*numShares + i]);
		}

		int eOutput = 0;
		if (curr_b > 0) { 
			for (int i = 0; i < numShares; i++) {
				eOutput ^= gf_mul(outputVals[i], invertMat[(deg)*numShares + i]);
			}
		}

		free(decodeMat);
		free(decodeMat2);
		free(invertMat);
		free(invertMat2);
		free(outputVals);
		free(outputVals2);
		if (gOutput0 == gOutput1) {
			if (curr_b == 0) {
				return 1;
			} else {
				return 1;
			}
		}
		curr_b++; 
	}
	return 1;
	printf("THIS SHOULDNT PRINT\n");
}