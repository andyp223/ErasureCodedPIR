#ifndef _SHAMIR_DPF_H
#define _SHAMIR_DPF_H

void genShamirCoeffs(int n, int t, int numRounds, uint128_t index, uint8_t*** coeffs_x, uint8_t*** coeffs_y); 
void genShamirDPF(int log_domainSize, uint128_t index, uint8_t b, int dataSize, int t, int p, uint8_t*** key_output);
void genOptShamirDPF(int log_domainSize, uint128_t index, int t, int p, int numRounds, uint8_t*** key_output, uint8_t*** coeffs_x, uint8_t*** coeffs_y);

void evalShamirDPF(int p, int party_index, int log_domainSize, uint8_t* key, uint128_t index, int dataSize, uint8_t* result);
void evalAllShamirDPF(int p, int party_index, int log_domainSize, uint8_t* key, int dataSize, uint8_t** output);
void genHollantiDPF(int log_domainSize, uint128_t index, int t, int p, int numRounds, int rho, uint8_t*** key_output);

#endif