#include <openssl/rand.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <vector>

#include "coding.h"
#include "params.h"

int NUM_PARTIES = 0;
int MODE = -1;
int M = 4;

int NUM_FILES = 0;
uint32_t LOG_NUM_FILES = 0;
uint32_t FILE_SIZE_BYTES = 0;
uint32_t PAYLOAD_SIZE_BYTES = 0; 

int NUM_ENCODED_FILES = 0;
int LOG_NUM_ENCODED_FILES = 0;
int ENCODED_FILE_SIZE_BYTES = 0; 
int ENCODED_PAYLOAD_SIZE_BYTES = 0; 

int ENCODE_ACROSS = -1;
int NUM_ROUNDS = 0; 
int RHO = 2; // default is 1 
int K = 0; 
int T = 0;
int R = 0;
int B = 0; 
int NUM_RESPONSES = 0;

int IS_HERMITE = 0;
int D = 0;
int CHECK_MAC = 0;
int MAC_SIZE_BYTES = 32;

uint32_t** MAPPING_INDEX = NULL;
int WOODRUFF_D = 0;
int WOODRUFF_M = 0; 
int WOODRUFF_DERIVATIVE = 0;

std::vector<int> RSS_SHARE_TO_PARTY{};
std::vector<std::vector<int>> RSS_SUBSETS{}; // parties to key received mapping 
uint8_t** PARTY_TO_POSITION_MAPPING = NULL; // party index to key position mapping
int NUM_RSS_KEYS = 0;

// pre generated covering design for p = 5, m = 3, t = 2
std::vector<int> CD532_SHARE_TO_PARTY{};
std::vector<std::vector<int>> CD532_SUBSETS{
    { 2,3 },
    { 1,1 },
    { 1,1 },
    { 0,3 },
    { 0,2 },
}; // parties to key received mapping 
std::vector<std::vector<int>> CD532_PARTY_TO_POSITION_MAPPING = 
    {
    {255,255,0,1}, 
    {255,0,255,255}, 
    {255,0,255,255}, 
    {0,255,255,1}, 
    {0,255,1,255}}; // party index to key position mapping
int NUM_CD532_KEYS = 2;
int NUM_CD532_KEYS_NEEDED = 4; 

// pre generated covering design for p = 5, m = 3, t = 2
std::vector<int> CD632_SHARE_TO_PARTY{};
std::vector<std::vector<int>> CD632_SUBSETS{
    { 0,1,3 },
    { 1,2,4 },
    { 2,3,5 },
    { 0,3,4 },
    { 1,4,5 },
    { 0,2,5 },
}; // parties to key received mapping 
std::vector<std::vector<int>> CD632_PARTY_TO_POSITION_MAPPING = 
    {
    {0,1,255,2,255,255}, 
    {255,0,1,255,2,255}, 
    {255,255,0,1,255,2}, 
    {0,255,255,1,2,255}, 
    {255,0,255,255,1,2},
    {0,255,1,255,255,2}}; // party index to key position mapping
int NUM_CD632_KEYS = 3;
int NUM_CD632_KEYS_NEEDED = 6; 


// pre generated covering design for p = 7, m = 3, t = 2
std::vector<int> CD732_SHARE_TO_PARTY{};
std::vector<std::vector<int>> CD732_SUBSETS{
    { 3,4,5,6 },
    { 1,2,5,6 },
    { 1,2,3,4 },
    { 0,2,4,6 },
    { 0,2,3,5 },
    { 0,1,4,5 },
    { 0,1,3,6 },
}; 

std::vector<std::vector<int>> CD732_PARTY_TO_POSITION_MAPPING = 
    {
    {255,255,255,0,1,2,3}, 
    {255,0,1,255,255,2,3}, 
    {255,0,1,2,3,255,255}, 
    {0,255,1,255,2,255,3}, 
    {0,255,1,2,255,3,255}, 
    {0,1,255,255,2,3,255}, 
    {0,1,255,2,255,255,3}}; // party index to key position mapping
int NUM_CD732_KEYS = 4;
int NUM_CD732_KEYS_NEEDED = 7; 

// pre generated covering design for p = 8, m = 4, t = 2
std::vector<int> CD842_SHARE_TO_PARTY{};
std::vector<std::vector<int>> CD842_SUBSETS{
    { 2,3,4 },
    { 1,3,5 },
    { 1,3,5 },
    { 1,2,4 },
    { 0,3,4 },
    { 0,2,5 },
    { 0,2,5 },
    { 0,1,4 },
}; 
std::vector<std::vector<int>> CD842_PARTY_TO_POSITION_MAPPING = 
    {
    {255,255,0,1,2,255}, 
    {255,0,255,1,255,2}, 
    {255,0,255,0,255,2}, 
    {255,0,1,255,2,255}, 
    {0,255,255,1,2,255}, 
    {0,255,1,255,255,2},
    {0,255,1,255,255,2},
    {0,1,255,255,2,255}};  // party index to key position mapping

int NUM_CD842_KEYS = 3;
int NUM_CD842_KEYS_NEEDED = 6; 

// pre generated covering design for p = 8, m = 3, t = 2
std::vector<int> CD832_SHARE_TO_PARTY{};
std::vector<std::vector<int>> CD832_SUBSETS{
    { 3,4,5,6,8,9,10 },
    { 1,2,5,6,8,9,10 },
    { 1,2,3,4,7,9,10 },
    { 0,2,4,6,7,9,10 },
    { 0,2,3,5,7,8,10 },
    { 0,1,4,5,7,8,10 },
    { 0,1,3,6,7,8,9 },
    { 0,1,2,3,4,5,6 }
}; 

std::vector<std::vector<int>> CD832_PARTY_TO_POSITION_MAPPING = 
    {
    {255,255,255,0,1,2,3,255,4,5,6}, 
    {255,0,1,255,255,2,3,255,4,5,6}, 
    {255,0,1,2,3,255,255,4,255,5,6}, 
    {0,255,1,255,2,255,3,4,255,5,6}, 
    {0,255,1,2,255,3,255,4,5,255,6}, 
    {0,1,255,255,2,3,255,4,5,255,6}, 
    {0,1,255,2,255,255,3,4,5,6,255},
    {0,1,2,3,4,5,6,255,255,255,255 }}; // party index to key position mapping
int NUM_CD832_KEYS = 7;
int NUM_CD832_KEYS_NEEDED = 11;

// pre generated covering design for p = 9, m = 4, t = 2
std::vector<int> CD942_SHARE_TO_PARTY{};
std::vector<std::vector<int>> CD942_SUBSETS{
    { 2,3,4,2,2 },
    { 1,3,4,7,1 },
    { 1,2,5,6,1 },
    { 1,2,5,6,1 },
    { 0,3,4,5,6 },
    { 0,2,4,6,7 },
    { 0,2,3,5,7 },
    { 0,1,4,5,7 },
    { 0,1,3,6,7 },
}; 
std::vector<std::vector<int>> CD942_PARTY_TO_POSITION_MAPPING = 
    {
    {255,255,0,1,2,255,255,255},
    {255,0,255,1,2,255,255,3}, 
    {255,0,1,255,255,2,3,255}, 
    {255,0,1,255,255,2,3,255}, 
    {0,255,255,1,2,3,4,255}, 
    {0,255,1,255,2,255,3,4}, 
    {0,255,1,2,255,3,255,4},
    {0,1,255,255,2,3,255,4},
    {0,1,255,2,255,255,3,4}
    };  // party index to key position mapping

int NUM_CD942_KEYS = 5;
int NUM_CD942_KEYS_NEEDED = 8; 

// pre generated covering design for p = 10, m = 4, t = 2
std::vector<int> CD1042_SHARE_TO_PARTY{};
std::vector<std::vector<int>> CD1042_SUBSETS{
    { 3,4,5,6,7,8 },
    { 1,2,6,7,8,1 },
    { 1,2,6,7,8,1 },
    { 1,2,3,4,5,8 },
    { 0,2,4,5,7,0 },
    { 0,2,3,5,7,0 },
    { 0,2,3,4,6,8 },
    { 0,1,4,5,6,0 },
    { 0,1,3,5,6,0 },
    { 0,1,3,4,7,8 }}; 
std::vector<std::vector<int>> CD1042_PARTY_TO_POSITION_MAPPING = 
    {
    {255,255,255,0,1,2,3,4,5},
    {255,0,1,255,255,255,2,3,4}, 
    {255,0,1,255,255,255,2,3,4}, 
    {255,0,1,2,3,4,255,255,5}, 
    {0,255,1,255,2,3,255,4,255}, 
    {0,255,1,2,255,3,255,4,255}, 
    {0,255,1,2,3,255,4,255,5},
    {0,1,255,255,2,3,4,255,255},
    {0,1,255,2,255,3,4,255,255},
    {0,1,255,2,3,255,255,4,5}};  // party index to key position mapping

int NUM_CD1042_KEYS = 6;
int NUM_CD1042_KEYS_NEEDED = 9; 


// pre generated covering design for p = 9, m = 3, t = 2
std::vector<int> CD932_SHARE_TO_PARTY{};
std::vector<std::vector<int>> CD932_SUBSETS{
    { 1,2,4,5,7,8,10,11 },
    { 0,2,3,5,6,8,10,11 },
    { 0,1,3,4,6,7,10,11 },
    { 1,2,3,5,6,7,9,11 },
    { 0,2,3,4,7,8,9,11 },
    { 0,1,4,5,6,8,9,11 },
    { 1,2,3,4,6,8,9,10 },
    { 0,2,4,5,6,7,9,10 },
    { 0,1,3,5,7,8,9,10 },
}; // parties to key received mapping 
std::vector<std::vector<int>> CD932_PARTY_TO_POSITION_MAPPING = 
    {
    {255,0,1,255,2,3,255,4,5,255,6,7},
    {0,255,1,2,255,3,4,255,5,255,6,7},
    {0,1,255,2,3,255,4,5,255,255,6,7},
    {255,0,1,2,255,3,4,5,255,6,255,7},
    {0,255,1,2,3,255,255,4,5,6,255,7},
    {0,1,255,255,2,3,4,255,5,6,255,7},
    {255,0,1,2,3,255,4,255,5,6,7,255},
    {0,255,1,255,2,3,4,5,255,6,7,255},
    {0,1,255,2,255,3,255,4,5,6,7,255},
    }; // party index to key position mapping
int NUM_CD932_KEYS = 8;
int NUM_CD932_KEYS_NEEDED = 12; 

// pre generated covering design for p = 14, m = 7, t = 2
std::vector<int> CD1472_SHARE_TO_PARTY{};
std::vector<std::vector<int>> CD1472_SUBSETS{
    { 0,2,5 },
    { 2,3,4 },
    { 2,4,5 },
    { 0,1,2 },
    { 0,3,4 },
    { 0,1,2 },
    { 1,4,5 },
    { 1,3,5 },
    { 1,4,5 },
    { 0,3,4 },
    { 2,3,5 },
    { 1,3,5 }, 
    { 0,3,4 },
    { 0,1,2 }}; 
std::vector<std::vector<int>> CD1472_PARTY_TO_POSITION_MAPPING = 
    {
    {0,255,1,255,255,2},
    {255,255,0,1,2,255}, 
    {255,255,0,255,1,2}, 
    {0,1,2,255,255,255}, 
    {0,255,255,1,2,255}, 
    {0,1,2,255,255,255}, 
    {255,0,255,255,1,2},
    {255,0,255,1,255,2},
    {255,0,255,255,1,2},
    {0,255,255,1,2,255},
    {255,255,0,1,255,2},
    {255,0,255,1,255,2},
    {0,255,255,1,2,255},
    {0,1,2,255,255,255}};  // party index to key position mapping

int NUM_CD1472_KEYS = 3;
int NUM_CD1472_KEYS_NEEDED = 6; 


// pre generated covering design for p = 12, m = 6, t = 2
std::vector<int> CD1262_SHARE_TO_PARTY{};
std::vector<std::vector<int>> CD1262_SUBSETS{
    { 2,3,4 },
    { 1,3,5 },
    { 1,3,5 },
    { 1,3,5 },
    { 1,2,4 },
    { 1,2,4 },
    { 0,3,4 },
    { 0,3,4 },
    { 0,2,5 },
    { 0,2,5 },
    { 0,2,5 },
    { 0,1,4 }}; 
std::vector<std::vector<int>> CD1262_PARTY_TO_POSITION_MAPPING = 
    {
    {255,255,0,1,2,255},
    {255,0,255,1,255,2}, 
    {255,0,255,1,255,2}, 
    {255,0,255,1,255,2}, 
    {255,0,1,255,2,255}, 
    {255,0,1,255,2,255}, 
    {0,255,255,1,2,255},
    {0,255,255,1,2,255},
    {0,255,1,255,255,2},
    {0,255,1,255,255,2},
    {0,255,1,255,255,2},
    {0,1,255,255,2,255}};  // party index to key position mapping

int NUM_CD1262_KEYS = 3;
int NUM_CD1262_KEYS_NEEDED = 6; 

// pre generated covering design for p = 16, m = 8, t = 2
std::vector<int> CD1682_SHARE_TO_PARTY{};
std::vector<std::vector<int>> CD1682_SUBSETS{
    { 2,3,4 },
    { 1,3,5 },
    { 1,3,5 },
    { 1,3,5 },
    { 1,3,5 },
    { 1,2,4 },
    { 1,2,4 },
    { 1,2,4 },
    { 0,3,4 },
    { 0,3,4 },
    { 0,3,4 },
    { 0,2,5 },
    { 0,2,5 },
    { 0,2,5 },
    { 0,2,5 },
    { 0,1,4 }}; 
std::vector<std::vector<int>> CD1682_PARTY_TO_POSITION_MAPPING = 
    {
    {255,255,0,1,2,255},
    {255,0,255,1,255,2}, 
    {255,0,255,1,255,2}, 
    {255,0,255,1,255,2}, 
    {255,0,255,1,255,2}, 
    {255,0,1,255,2,255}, 
    {255,0,1,255,2,255}, 
    {255,0,1,255,2,255}, 
    {0,255,255,1,2,255},
    {0,255,255,1,2,255},
    {0,255,255,1,2,255},
    {0,255,1,255,255,2},
    {0,255,1,255,255,2},
    {0,255,1,255,255,2},
    {0,255,1,255,255,2},
    {0,1,255,255,2,255}};  // party index to key position mapping

int NUM_CD1682_KEYS = 3;
int NUM_CD1682_KEYS_NEEDED = 6; 

std::vector<int> CD_SHARE_TO_PARTY = CD532_SHARE_TO_PARTY;
std::vector<std::vector<int>> CD_SUBSETS = CD532_SUBSETS; // parties to key received mapping 
// extern std::vector<std::vector<int>> CD732_KEY_TO_POSITION_MAPPING; // key to position mapping
std::vector<std::vector<int>> CD_PARTY_TO_POSITION_MAPPING = CD532_PARTY_TO_POSITION_MAPPING; // party index to key position mapping
int NUM_CD_KEYS = NUM_CD532_KEYS;
int NUM_CD_KEYS_NEEDED = NUM_CD532_KEYS_NEEDED;
std::vector<std::vector<int>> MAPPING = CD_SUBSETS;

int isRss = 1;


void makeCombiUtil(std::vector<std::vector<int> >& ans,
    std::vector<int>& tmp, int n, int left, int k)
{
    // Pushing this vector to a vector of vector
    if (k == 0) {
        ans.push_back(tmp);
        return;
    }
 
    // i iterates from left to n. First time
    // left will be 1
    for (int i = left; i <= n; ++i)
    {
        tmp.push_back(i);
        makeCombiUtil(ans, tmp, n, i + 1, k - 1);
 
        // Popping out last inserted element
        // from the vector
        tmp.pop_back();
    }
}
 
// Prints all combinations of size k of numbers
// from 1 to n.
std::vector<std::vector<int>>makeCombi(int n, int k)
{
    std::vector<std::vector<int> > ans;
    std::vector<int> tmp;
    makeCombiUtil(ans, tmp, n, 1, k);
    return ans;
}

/* Set parameters for entire system. */

// 0 = DPF Tree, 1 = Multiparty, 2 = Shamir, 3 = Hollanti, 4 = CD, 5 = Woodruff
void setModeParams(int mode) {
    enum Mode {Tree, Multiparty, Shamir, Hollanti, CD, Woodruff, Goldberg};

    switch (mode) {
    case Tree:
        assert(T == 1);
        NUM_PARTIES = K + R + T + (2*B) + (RHO - 1);
        ENCODE_ACROSS = 1; 
        break;
    case Multiparty:
        NUM_PARTIES = T + K + R + (2*B);
        ENCODE_ACROSS = 1;
        break;
    case Shamir:
        NUM_PARTIES = (int)ceil(double(2*T + 2*K)/2 + R + 2*B + (RHO - 1));
        // NUM_PARTIES = 2*T + 2*K + R + 2*B + (RHO - 1);
        IS_HERMITE = 1;
        D = 2;
        ENCODE_ACROSS = 0;
        break;
    case Hollanti:
        NUM_PARTIES = T + K + R + (2*B) + (RHO - 1);
        ENCODE_ACROSS = 0;
        break;
    case CD:
        if ((K ==4) && (B == 2)) {
            NUM_PARTIES = 16;
        } else if ((K == 3) && (B == 2)) {
            NUM_PARTIES = 14;
        } else if ((K == 2) && (B == 1)) {
            M = 2; 
            NUM_PARTIES = 8;
        } else  {
            NUM_PARTIES = T + K + R + (2*B) + M;
        }
        ENCODE_ACROSS = 1;
        printf("NUM PARTIES: %d\n", NUM_PARTIES);
        break;
    case Woodruff:
        assert(K == 1);
        if (WOODRUFF_DERIVATIVE) {
            NUM_PARTIES = int(ceil((double(2*T + 1)/2))) + R + 2*B; 
        } else {
            NUM_PARTIES = 2*T + 1 + R + 2*B; 
        }
        ENCODE_ACROSS = 0;
        break;
    case Goldberg:
        NUM_PARTIES = T + K + R + (2*B) + (RHO - 1);
        ENCODE_ACROSS = 0;
        break;
    default:
        printf("Error: Should never reach here.\n");
    }

}

void setSystemParams(int logNumFiles, int fileSizeBytes, int t, int k, int r, int b, int rho, int checkMac, int mode) {
    RHO = rho;
    K = k; 
    T = t;
    R = r;
    B = b; 
    NUM_RESPONSES = NUM_PARTIES - R;

    NUM_FILES = pow(2,logNumFiles);
    LOG_NUM_FILES = logNumFiles;
    PAYLOAD_SIZE_BYTES = fileSizeBytes;
    FILE_SIZE_BYTES = fileSizeBytes;

    CHECK_MAC = checkMac;
    MODE = mode;
    setModeParams(mode);
    printf("NUM PARTIES = %d\n", NUM_PARTIES);

    if (ENCODE_ACROSS) {
        LOG_NUM_ENCODED_FILES = ceil(log2((int)ceil((double)NUM_FILES/k)));
        NUM_ENCODED_FILES = pow(2, LOG_NUM_ENCODED_FILES);
        ENCODED_PAYLOAD_SIZE_BYTES = FILE_SIZE_BYTES; 
        ENCODED_FILE_SIZE_BYTES = FILE_SIZE_BYTES; 

        if (CHECK_MAC) {
            FILE_SIZE_BYTES += MAC_SIZE_BYTES;
            ENCODED_FILE_SIZE_BYTES += MAC_SIZE_BYTES;
        }
    }else {
        NUM_ENCODED_FILES = NUM_FILES;
        LOG_NUM_ENCODED_FILES = LOG_NUM_FILES;
        ENCODED_PAYLOAD_SIZE_BYTES = ceil(float(PAYLOAD_SIZE_BYTES/double(k))); 
        ENCODED_FILE_SIZE_BYTES = ceil(float(FILE_SIZE_BYTES/double(k))); 

        if (CHECK_MAC) {
            FILE_SIZE_BYTES += MAC_SIZE_BYTES;
            ENCODED_FILE_SIZE_BYTES += ceil(float(FILE_SIZE_BYTES/double(k)));
        }
    }

    // NUM_ROUNDS = 1; 
    if (K == 1) {
        NUM_ROUNDS = 1; 
    } else {
        NUM_ROUNDS = K/RHO; 
    }
    //rintf("NUM_ROUNDS: %d\n",NUM_ROUNDS);
    //printf("NUM_ROUNDS: %d\n",NUM_ROUNDS);

    // generate subsets for RSS 
    //printf("%d\n",(NUM_PARTIES - T) * choose(NUM_PARTIES,T) / NUM_PARTIES);

    // set covering design
    if ((T == 2) && (NUM_PARTIES == 5) && (M == 1)) {
        CD_SHARE_TO_PARTY = CD532_SHARE_TO_PARTY;
        CD_SUBSETS = CD532_SUBSETS;
        CD_PARTY_TO_POSITION_MAPPING = CD532_PARTY_TO_POSITION_MAPPING;
        NUM_CD_KEYS = NUM_CD532_KEYS; 
        NUM_CD_KEYS_NEEDED = NUM_CD532_KEYS_NEEDED;
        isRss = 0;
    } else if ((T == 2) && (NUM_PARTIES == 7) && (M == 1)) {
        CD_SHARE_TO_PARTY = CD732_SHARE_TO_PARTY;
        CD_SUBSETS = CD732_SUBSETS;
        CD_PARTY_TO_POSITION_MAPPING = CD732_PARTY_TO_POSITION_MAPPING;
        NUM_CD_KEYS = NUM_CD732_KEYS; 
        NUM_CD_KEYS_NEEDED = NUM_CD732_KEYS_NEEDED;
        isRss = 0;
    } else if ((T == 2) && (NUM_PARTIES == 6) && (M == 1)) {
        CD_SHARE_TO_PARTY = CD632_SHARE_TO_PARTY;
        CD_SUBSETS = CD632_SUBSETS;
        CD_PARTY_TO_POSITION_MAPPING = CD632_PARTY_TO_POSITION_MAPPING;
        NUM_CD_KEYS = NUM_CD632_KEYS; 
        NUM_CD_KEYS_NEEDED = NUM_CD632_KEYS_NEEDED;
        isRss = 0;
    } else if ((T == 2) && (NUM_PARTIES == 8) && (M == 1)) {
        CD_SHARE_TO_PARTY = CD832_SHARE_TO_PARTY;
        CD_SUBSETS = CD832_SUBSETS;
        CD_PARTY_TO_POSITION_MAPPING = CD832_PARTY_TO_POSITION_MAPPING;
        NUM_CD_KEYS = NUM_CD832_KEYS; 
        NUM_CD_KEYS_NEEDED = NUM_CD832_KEYS_NEEDED;
        isRss = 0;
    } else if ((T == 2) && (NUM_PARTIES == 9) && (M == 1)) {
        CD_SHARE_TO_PARTY = CD932_SHARE_TO_PARTY;
        CD_SUBSETS = CD932_SUBSETS;
        CD_PARTY_TO_POSITION_MAPPING = CD932_PARTY_TO_POSITION_MAPPING;
        NUM_CD_KEYS = NUM_CD932_KEYS; 
        NUM_CD_KEYS_NEEDED = NUM_CD932_KEYS_NEEDED;
        isRss = 0;
    } else if ((T == 2) && (NUM_PARTIES == 8) && (M == 2)) {
        CD_SHARE_TO_PARTY = CD842_SHARE_TO_PARTY;
        CD_SUBSETS = CD842_SUBSETS;
        CD_PARTY_TO_POSITION_MAPPING = CD842_PARTY_TO_POSITION_MAPPING;
        NUM_CD_KEYS = NUM_CD842_KEYS; 
        NUM_CD_KEYS_NEEDED = NUM_CD842_KEYS_NEEDED;
        isRss = 0;
    } else if ((T == 2) && (NUM_PARTIES == 9) && (M == 2)) {
        CD_SHARE_TO_PARTY = CD942_SHARE_TO_PARTY;
        CD_SUBSETS = CD942_SUBSETS;
        CD_PARTY_TO_POSITION_MAPPING = CD942_PARTY_TO_POSITION_MAPPING;
        NUM_CD_KEYS = NUM_CD942_KEYS; 
        NUM_CD_KEYS_NEEDED = NUM_CD942_KEYS_NEEDED;
        isRss = 0;
    } else if ((T == 2) && (NUM_PARTIES == 10) && (M == 2)) {
        CD_SHARE_TO_PARTY = CD1042_SHARE_TO_PARTY;
        CD_SUBSETS = CD1042_SUBSETS;
        CD_PARTY_TO_POSITION_MAPPING = CD1042_PARTY_TO_POSITION_MAPPING;
        NUM_CD_KEYS = NUM_CD1042_KEYS; 
        NUM_CD_KEYS_NEEDED = NUM_CD1042_KEYS_NEEDED;
        isRss = 0;
    } else if ((T == 2) && (NUM_PARTIES == 12) && (M == 4)) {
        CD_SHARE_TO_PARTY = CD1262_SHARE_TO_PARTY;
        CD_SUBSETS = CD1262_SUBSETS;
        CD_PARTY_TO_POSITION_MAPPING = CD1262_PARTY_TO_POSITION_MAPPING;
        NUM_CD_KEYS = NUM_CD1262_KEYS; 
        NUM_CD_KEYS_NEEDED = NUM_CD1262_KEYS_NEEDED;
        isRss = 0;
    } else if ((T == 2) && (NUM_PARTIES == 16) && (M == 4)) {
        // printf("ENTERS HERE\n");
        CD_SHARE_TO_PARTY = CD1682_SHARE_TO_PARTY;
        CD_SUBSETS = CD1682_SUBSETS;
        CD_PARTY_TO_POSITION_MAPPING = CD1682_PARTY_TO_POSITION_MAPPING;
        NUM_CD_KEYS = NUM_CD1682_KEYS; 
        NUM_CD_KEYS_NEEDED = NUM_CD1682_KEYS_NEEDED;
        isRss = 0;
    } else if ((T == 2) && (NUM_PARTIES == 14) && (M == 4)) {
        // printf("ENTERS HERE\n");
        CD_SHARE_TO_PARTY = CD1472_SHARE_TO_PARTY;
        CD_SUBSETS = CD1472_SUBSETS;
        CD_PARTY_TO_POSITION_MAPPING = CD1472_PARTY_TO_POSITION_MAPPING;
        NUM_CD_KEYS = NUM_CD1472_KEYS; 
        NUM_CD_KEYS_NEEDED = NUM_CD1472_KEYS_NEEDED;
        isRss = 0;
    }

    // printf("GETS HERE\n");

    if ((t >= 1) && (isRss != 0)) {
        PARTY_TO_POSITION_MAPPING = (uint8_t**) malloc(NUM_PARTIES * sizeof(uint8_t*));
        for (int i = 0; i < NUM_PARTIES; i++) {
            PARTY_TO_POSITION_MAPPING[i] = (uint8_t*)malloc(choose(NUM_PARTIES,T));
        }
        for (int i = 0; i < pow(2,NUM_PARTIES); i++) {
            if (countNumOnes(i) == t) {
                RSS_SHARE_TO_PARTY.push_back(i);
            }
        }
        for (int j = 0; j < NUM_PARTIES; j++) {
            int curr = 0;
            std::vector<int> tmp;
            RSS_SUBSETS.push_back(tmp);
        }
        NUM_RSS_KEYS = choose(NUM_PARTIES, T)*(NUM_PARTIES - T) / NUM_PARTIES;
    }

    WOODRUFF_D = 2;
    int tmp = WOODRUFF_D + 1; 

    while (choose(tmp,WOODRUFF_D) < NUM_FILES) {
        tmp++;
    }

    WOODRUFF_M = tmp; 
    MAPPING = makeCombi(WOODRUFF_M, WOODRUFF_D);
    MAPPING_INDEX = (uint32_t**)malloc(NUM_FILES*sizeof(uint32_t*));
    for (int i = 0; i < NUM_FILES; i++) {
        MAPPING_INDEX[i] = (uint32_t*)malloc(WOODRUFF_D);
        memset(MAPPING_INDEX[i],0,D);
    }

    for (int i = 0 ; i < NUM_FILES; i++) {
        for (int j = 0; j < WOODRUFF_D; j++) {
            MAPPING_INDEX[i][j] = MAPPING[i][j];
        }
    }

}

void freeParams() {
    if (PARTY_TO_POSITION_MAPPING) {
        for (int i = 0; i < NUM_PARTIES; i++) {
            free(PARTY_TO_POSITION_MAPPING[i]);
        }
        free(PARTY_TO_POSITION_MAPPING);
    }
}