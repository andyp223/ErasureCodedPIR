#// include <openssl/rand.h>
#include <string.h>
#include <math.h>
#include <assert.h>

#include "coding.h"
#include "utils.h"

// function coefficients are always listed from constant to the smallest degree coefficient
int divideTwoFuncs(uint8_t* funcA, uint8_t* funcB, uint8_t funcADegree, uint8_t funcBDegree, uint8_t* output, uint8_t outputSize) {
    assert(funcADegree > funcBDegree); 
    assert((funcADegree - funcBDegree + 1) == outputSize); 

    uint8_t outputDegree = funcADegree - funcBDegree;

    uint8_t* remainder = (uint8_t*)malloc(funcADegree + 1);
    memcpy(remainder, funcA, funcADegree + 1); 


    for (int i = 0; i < outputDegree + 1; i++) {
        uint8_t multiplier = gf_mul(gf_inv(funcB[funcBDegree]), remainder[funcADegree - i]);
        output[outputDegree - i] = multiplier; 

        // subtract out funcB * multiplier from the remainder 
        for (int j = 0; j < funcBDegree + 1; j++) {
            remainder[funcADegree - i - j] ^= gf_mul(multiplier, funcB[funcBDegree - j]);
        }

        assert(remainder[funcADegree - i] == 0);
    }
 
    for (int i = 0; i < funcBDegree; i++) {
        if (remainder[i] != 0) {
            return -1;
        }
    }
    return 1; 
}

void computeMatrixTimesResponse(uint8_t* matrix, uint8_t* responses, int size, uint8_t* output) {
    // ith output position 
    for (int i = 0; i < size; i++) {
        output[i] = 0;
        for (int j = 0; j < size; j++) {
            output[i] ^= gf_mul(responses[j], matrix[i*size + j]);
        }
    }
}

void calcFuncCoeffs(uint8_t evalPoint, uint8_t funcDegree, uint8_t* coeffs) {
    for (int i = 0; i < funcDegree + 1; i++) {
        coeffs[i] = gf_pow(evalPoint, i);
    }
}

void calcFuncDerivCoeffs(uint8_t evalPoint, uint8_t funcDegree, uint8_t* coeffs) {
    for (int i = 0; i < funcDegree + 1; i++) {
        coeffs[i] = (i == 0) ? 0 : gf_mul((i%2),gf_pow(evalPoint, i-1));
    }
}

void hermiteInterpolationSemihonest(uint8_t* evalPoints, uint8_t numPoints, uint8_t* evals, uint8_t* derivEvals, uint8_t funcDegree, uint8_t* output) {
    assert(2*numPoints >= funcDegree + 1);

    uint8_t* genMatrix = (uint8_t*)malloc((funcDegree + 1)*(funcDegree + 1));
    uint8_t* outputEvals = (uint8_t*)malloc(funcDegree + 1);

    for (int i = 0; i < funcDegree + 1; i++) {
        int index = floor(i/2);
        //printf("%d\n",index);
        int isDeriv = i % 2; 

        if (isDeriv) {
            calcFuncDerivCoeffs(evalPoints[index],funcDegree,&(genMatrix[i*(funcDegree + 1)]));
            outputEvals[i] = derivEvals[index];
        } else {
            calcFuncCoeffs(evalPoints[index],funcDegree,&(genMatrix[i*(funcDegree + 1)]));
            outputEvals[i] = evals[index];
        }
    }
    uint8_t* invertMat = (uint8_t*)malloc((funcDegree + 1)*(funcDegree + 1));
    gf_invert_matrix(genMatrix, invertMat, funcDegree+1);

    computeMatrixTimesResponse(invertMat, outputEvals, funcDegree + 1, output);

    free(genMatrix);
    free(outputEvals);
    free(invertMat); 
}

void calcMaliciousFuncCoeffs(uint8_t evalPoint, uint8_t resp, uint8_t funcDegree, uint8_t b, uint8_t* coeffs) {
    for (int i = 0; i < b; i++) {
        coeffs[i] = gf_mul(resp, gf_pow(evalPoint, i-1));
    }

    for (int i = 0; i < funcDegree + b + 1; i++) {
        coeffs[b + i] = gf_pow(evalPoint, i);
    }
}

void calcMaliciousFuncDerivCoeffs(uint8_t evalPoint, uint8_t resp, uint8_t derivResp, uint8_t funcDegree, uint8_t b, uint8_t* coeffs) {
    memset(coeffs,0, funcDegree + 2*b + 1);

    for (int i = 0; i < b; i++) {
        coeffs[i] = gf_mul(derivResp, gf_pow(evalPoint, i));
    }

    for (int i = 0; i < b; i++) {
        coeffs[i] ^= (i == 0) ? 0 : gf_mul(resp, gf_mul((i%2),gf_pow(evalPoint, i-1)));
    }

    for (int i = 0; i < funcDegree + b + 1; i++) {
        coeffs[b + i] = (i == 0) ? 0 : gf_mul((i%2),gf_pow(evalPoint, i-1));
    }
}

void hermiteInterpolationMalicious(uint8_t* evalPoints, uint8_t numPoints, uint8_t* evals, 
    uint8_t* derivEvals, uint8_t funcDegree, uint8_t maxErrors, uint8_t* output) {

    assert(numPoints >= floor((funcDegree + 1)/2) + 2*maxErrors);

    int b = 2*maxErrors; 

    while (b > 0) {
        // printf("%d\n",b);
        uint8_t* genMatrix = (uint8_t*)malloc((funcDegree + 2*b + 1)*(funcDegree + 2*b + 1));
        uint8_t* outputEvals = (uint8_t*)malloc(funcDegree + 2*b + 1);

        // generate berlekamp welch matrix here
        for (int i = 0; i < funcDegree + 2*b + 1; i++) {
            int index = floor(i/2);
            int isDeriv = i % 2; 
            uint8_t pt = evalPoints[index]; 

            if (isDeriv) {
                calcMaliciousFuncDerivCoeffs(pt,evals[index],derivEvals[index],funcDegree,b,&(genMatrix[i*(funcDegree + 2*b + 1)]));
                outputEvals[i] = gf_mul(derivEvals[index],gf_pow(pt,b)) ^ gf_mul(evals[index],gf_mul((b % 2),gf_pow(pt,b-1)));
            } else {
                calcMaliciousFuncCoeffs(pt,evals[index],funcDegree,b,&(genMatrix[i*(funcDegree + 2*b + 1)]));
                outputEvals[i] = gf_mul(evals[index],gf_pow(pt,b));
            }
        }

        uint8_t* invertMat = (uint8_t*)malloc((funcDegree + 2*b + 1)*(funcDegree + 2*b + 1));

        // couldn't invert
        if (gf_invert_matrix(genMatrix, invertMat, funcDegree+2*b + 1) == -1) {
            b -= 1; 
            continue;
        }

        uint8_t* tmpOutput = (uint8_t*)malloc(funcDegree + 2*b + 1);

        computeMatrixTimesResponse(invertMat, outputEvals, funcDegree + 2*b + 1, tmpOutput);

        uint8_t* funcA = (uint8_t*)malloc(funcDegree + b + 1);
        memcpy(funcA, &(tmpOutput[b]), funcDegree + b + 1);
        uint8_t* funcB = (uint8_t*)malloc(b + 1);
        memcpy(funcB, &(tmpOutput[0]), b);
        funcB[b] = 1; 

        if ( divideTwoFuncs(funcA, funcB, funcDegree + b, b, output, funcDegree + 1) == -1) {
            b -= 1;
            continue;
        } else {
            return;
        }
        free(genMatrix);
        free(outputEvals); 
        free(tmpOutput); 
    }

    hermiteInterpolationSemihonest(evalPoints, numPoints, evals, derivEvals, funcDegree, output);
}

void lagrangeInterpolationSemihonest(uint8_t* evalPoints, uint8_t numPoints, 
    uint8_t* evals, uint8_t funcDegree, uint8_t* output) {

    assert(numPoints >= funcDegree + 1);

    uint8_t* genMatrix = (uint8_t*)malloc((funcDegree + 1)*(funcDegree + 1));
    uint8_t* outputEvals = (uint8_t*)malloc(funcDegree + 1);

    for (int i = 0; i < funcDegree + 1; i++) {
        calcFuncCoeffs(evalPoints[i],funcDegree,&(genMatrix[i*(funcDegree + 1)]));
        outputEvals[i] = evals[i];
    }
    uint8_t* invertMat = (uint8_t*)malloc((funcDegree + 1)*(funcDegree + 1));
    gf_invert_matrix(genMatrix, invertMat, funcDegree+1);

    computeMatrixTimesResponse(invertMat, outputEvals, funcDegree + 1, output);

    free(genMatrix);
    free(outputEvals);
    free(invertMat); 
}


void lagrangeInterpolationMalicious(uint8_t* evalPoints, uint8_t numPoints, uint8_t* evals, uint8_t funcDegree, uint8_t maxErrors, uint8_t* output) {
    assert(numPoints >= funcDegree + 1 + 2*maxErrors);
    int b = maxErrors; 

    while (b > 0) {
        uint8_t* genMatrix = (uint8_t*)malloc((funcDegree + 2*b + 1)*(funcDegree + 2*b + 1));
        uint8_t* outputEvals = (uint8_t*)malloc(funcDegree + 2*b + 1);

        // generate berlekamp welch matrix here
        for (int i = 0; i < funcDegree + 2*b + 1; i++) {
            uint8_t pt = evalPoints[i]; 
            calcMaliciousFuncCoeffs(pt,evals[i],funcDegree,b,&(genMatrix[i*(funcDegree + 2*b + 1)]));
            outputEvals[i] = gf_mul(evals[i],gf_pow(pt,b));
        }

        uint8_t* invertMat = (uint8_t*)malloc((funcDegree + 2*b + 1)*(funcDegree + 2*b + 1));

        // couldn't invert
        if (gf_invert_matrix(genMatrix, invertMat, funcDegree+2*b + 1) == -1) {
            b -= 1; 
            continue;
        }

        uint8_t* tmpOutput = (uint8_t*)malloc(funcDegree + 2*b + 1);

        computeMatrixTimesResponse(invertMat, outputEvals, funcDegree + 2*b + 1, tmpOutput);

        uint8_t* funcA = (uint8_t*)malloc(funcDegree + b + 1);
        memcpy(funcA, &(tmpOutput[b]), funcDegree + b + 1);
        uint8_t* funcB = (uint8_t*)malloc(b + 1);
        memcpy(funcB, &(tmpOutput[0]), b);
        funcB[b] = 1; 

        if ( divideTwoFuncs(funcA, funcB, funcDegree + b, b, output, funcDegree + 1) == -1) {
            b -= 1;
            continue;
        } else {
            return;
        }

        free(genMatrix);
        free(outputEvals); 
        free(tmpOutput); 
        free(funcA);
        free(funcB);
    }

    // no errors detected, just perform lagrange interpolation normally 
    lagrangeInterpolationSemihonest(evalPoints, numPoints, evals, funcDegree, output);
}