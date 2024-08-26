#ifndef _PARAMS_H
#define _PARAMS_H

#include <stdint.h>
#include <vector> 
#include "utils.h"


extern int NUM_PARTIES;

extern int NUM_FILES;
extern uint32_t LOG_NUM_FILES;
extern uint32_t FILE_SIZE_BYTES;
extern uint32_t PAYLOAD_SIZE_BYTES;


extern int NUM_ENCODED_FILES;
extern int LOG_NUM_ENCODED_FILES;
extern int ENCODED_PAYLOAD_SIZE_BYTES; 
extern int ENCODED_FILE_SIZE_BYTES; 
extern int ENCODE_ACROSS;

extern int NUM_ROUNDS; 
extern int RHO; // num symbols downloaded per round
extern int K; 
extern int T;
extern int R;
extern int B; 
extern int NUM_RESPONSES;
extern int MODE;

extern int IS_HERMITE;
extern int D; 

// MAC-enable flag
extern int MAC_SIZE_BYTES;
extern int CHECK_MAC;
// extern uint8_t** WY_INDEX_MAPPING;
extern int WOODRUFF_M;
extern int WOODRUFF_D;
extern int WOODRUFF_DERIVATIVE;
extern std::vector<std::vector<int>> MAPPING;
extern uint32_t** MAPPING_INDEX;

extern std::vector<int> RSS_SHARE_TO_PARTY;
extern std::vector<std::vector<int>> RSS_SUBSETS;
extern uint8_t** PARTY_TO_POSITION_MAPPING;
extern int NUM_RSS_KEYS;

extern std::vector<int> CD_SHARE_TO_PARTY;
extern std::vector<std::vector<int>> CD_SUBSETS; // parties to key received mapping 
// extern std::vector<std::vector<int>> CD732_KEY_TO_POSITION_MAPPING; // key to position mapping
extern std::vector<std::vector<int>> CD_PARTY_TO_POSITION_MAPPING; // party index to key position mapping
extern int NUM_CD_KEYS;
extern int NUM_CD_KEYS_NEEDED;

// extern std::vector<int> CD732_SHARE_TO_PARTY;
// extern std::vector<std::vector<int>> CD732_SUBSETS; // parties to key received mapping 
// // extern std::vector<std::vector<int>> CD732_KEY_TO_POSITION_MAPPING; // key to position mapping
// extern std::vector<std::vector<int>> CD732_PARTY_TO_POSITION_MAPPING; // party index to key position mapping
// extern int NUM_CD732_KEYS;

void setSystemParams(int logNumFiles, int fileSizeBytes, int t, int k, int r, int b, int rho, int checkMac, int mode);
void freeParams();
#endif
