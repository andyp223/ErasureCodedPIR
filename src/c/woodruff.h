#ifndef _WOODRUFF_H
#define _WOODRUFF_H


#ifndef SWIG
    typedef unsigned __int128 uint128_t;
#endif

void genWoodruffVs(int t, int m, uint8_t** v);

void genWoodruffQuery(uint128_t index, int t, int p, int m, uint8_t** v, uint8_t** key_output);
#endif