#ifndef _INTERPOLATION_H
#define _INTERPOLATION_H

#include <iostream>
#include <cassert>
#include <cstring>
#include <math.h>   

int divideTwoFuncs(uint8_t* funcA, uint8_t* funcB, uint8_t funcADegree, uint8_t funcBDegree, uint8_t* output, uint8_t outputSize);
void lagrangeInterpolationSemihonest(uint8_t* evalPoints, uint8_t numPoints, uint8_t* evals, uint8_t funcDegree, uint8_t* output);
void lagrangeInterpolationMalicious(uint8_t* evalPoints, uint8_t numPoints, uint8_t* evals, uint8_t funcDegree, uint8_t maxErrors, uint8_t* output);
void hermiteInterpolationSemihonest(uint8_t* evalPoints, uint8_t numPoints, uint8_t* evals, uint8_t* derivEvals, uint8_t funcDegree, uint8_t* output);
void hermiteInterpolationMalicious(uint8_t* evalPoints, uint8_t numPoints, uint8_t* evals, uint8_t* derivEvals, uint8_t funcDegree, uint8_t maxErrors, uint8_t* output);

#endif