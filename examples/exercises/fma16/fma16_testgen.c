// fma16_testgen.c
// David_Harris 8 February 2025
// Generate tests for 16-bit FMA
// SPDX-License-Identifier: Apache-2.0 WITH SHL-2.1

#include "softfloat.h"
#include "softfloat_types.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef union sp {
  float32_t v;
  float f;
} sp;

// lists of tests, terminated with 0x8000
uint16_t easyExponents[] = {15, 0x8000};
uint16_t easyFracts[] = {0, 0x200, 0x8000}; // 1.0 and 1.1

uint16_t medExponents[] = {0, 15, 31, 0x8000};
uint16_t medFracts[] = {0x00F, 0x0FF, 0x10F, 0x1FF,
                        0x20F, 0x2FF, 0x8000}; // 1.0 and 1.1

void softfloatInit(void) {
  softfloat_roundingMode = softfloat_round_minMag;
  softfloat_exceptionFlags = 0;
  softfloat_detectTininess = softfloat_tininess_beforeRounding;
}

float convFloat(float16_t f16) {
  float32_t f32;
  float res;
  sp r;

  // convert half to float for printing
  f32 = f16_to_f32(f16);
  r.v = f32;
  res = r.f;
  return res;
}

void genCase(FILE *fptr, float16_t x, float16_t y, float16_t z, int mul,
             int add, int negp, int negz, int roundingMode, int zeroAllowed,
             int infAllowed, int nanAllowed) {
  float16_t result;
  int op, flagVals;
  char calc[80], flags[80];
  float32_t x32, y32, z32, r32;
  float xf, yf, zf, rf;
  float16_t smallest;

  if (!mul)
    y.v = 0x3C00; // force y to 1 to avoid multiply
  if (!add)
    z.v = 0x0000; // force z to 0 to avoid add
  if (negp)
    x.v ^= 0x8000; // flip sign of x to negate p
  if (negz)
    z.v ^= 0x8000; // flip sign of z to negate z
  op = roundingMode << 4 | mul << 3 | add << 2 | negp << 1 | negz;
  //    printf("op = %02x rm %d mul %d add %d negp %d negz %d\n", op,
  //    roundingMode, mul, add, negp, negz);
  softfloat_exceptionFlags = 0; // clear exceptions
  result = f16_mulAdd(x, y, z); // call SoftFloat to compute expected result

  // Extract expected flags from SoftFloat
  sprintf(flags, "NV: %d OF: %d UF: %d NX: %d",
          (softfloat_exceptionFlags >> 4) % 2,
          (softfloat_exceptionFlags >> 2) % 2,
          (softfloat_exceptionFlags >> 1) % 2, (softfloat_exceptionFlags) % 2);
  // pack these four flags into one nibble, discarding DZ flag
  flagVals =
      softfloat_exceptionFlags & 0x7 | ((softfloat_exceptionFlags >> 1) & 0x8);

  // convert to floats for printing
  xf = convFloat(x);
  yf = convFloat(y);
  zf = convFloat(z);
  rf = convFloat(result);
  if (mul)
    if (add)
      sprintf(calc, "%f * %f + %f = %f", xf, yf, zf, rf);
    else
      sprintf(calc, "%f * %f = %f", xf, yf, rf);
  else
    sprintf(calc, "%f + %f = %f", xf, zf, rf);

  // omit denorms, which aren't required for this project
  smallest.v = 0x0400;
  float16_t resultmag = result;
  resultmag.v &= 0x7FFF; // take absolute value
  if (f16_lt(resultmag, smallest) && (resultmag.v != 0x0000))
    fprintf(fptr, "// skip denorm: ");
  if ((softfloat_exceptionFlags) >> 1 % 2)
    fprintf(fptr, "// skip underflow: ");

  // skip special cases if requested
  if (resultmag.v == 0x0000 && !zeroAllowed)
    fprintf(fptr, "// skip zero: ");
  if ((resultmag.v == 0x7C00 || resultmag.v == 0x7BFF) && !infAllowed)
    fprintf(fptr, "// Skip inf: ");
  if (resultmag.v > 0x7C00 && !nanAllowed)
    fprintf(fptr, "// Skip NaN: ");

  // print the test case
  fprintf(fptr, "%04x_%04x_%04x_%02x_%04x_%01x // %s %s\n", x.v, y.v, z.v, op,
          result.v, flagVals, calc, flags);
}

void prepTests(uint16_t *e, uint16_t *f, char *testName, char *desc,
               float16_t *cases, FILE *fptr, int *numCases) {
  int i, j;

  // Loop over all of the exponents and fractions, generating and counting all
  // cases
  fprintf(fptr, "%s", desc);
  fprintf(fptr, "\n");
  *numCases = 0;
  for (i = 0; e[i] != 0x8000; i++)
    for (j = 0; f[j] != 0x8000; j++) {
      cases[*numCases].v = f[j] | e[i] << 10;
      *numCases = *numCases + 1;
    }
}

void genMulTests(uint16_t *e, uint16_t *f, int sgn, char *testName, char *desc,
                 int roundingMode, int zeroAllowed, int infAllowed,
                 int nanAllowed, int op) {
  // op = 0: only multiply; op = 1: only add; op = 2: both
  int i, j, k, l, numCases;
  float16_t x, y, z;
  float16_t cases[100000];
  FILE *fptr;
  char fn[80];

  sprintf(fn, "work/%s.tv", testName);
  if ((fptr = fopen(fn, "w")) == 0) {
    printf("Error opening to write file %s.  Does directory exist?\n", fn);
    exit(1);
  }
  prepTests(e, f, testName, desc, cases, fptr, &numCases);

  if (zeroAllowed) {
    cases[numCases].v = 0x0000;
    numCases++;
    cases[numCases].v = 0x8000;
    numCases++;
  }

  if (infAllowed) {
    cases[numCases].v = 0x7C00;
    numCases++;
    cases[numCases].v = 0xFC00;
    numCases++;
  }

  if (nanAllowed) {
    cases[numCases].v = 0x7E00;
    numCases++;
    cases[numCases].v = 0xFE00;
    numCases++;
  }
  z.v = 0x0000;
  for (i = 0; i < numCases; i++) {
    x.v = cases[i].v;

    if (op == 0) {
      z.v = 0x0000;
      for (j = 0; j < numCases; j++) {
        y.v = cases[j].v;
        for (l = 0; l <= sgn; l++) {
          y.v ^= (l << 15);
          genCase(fptr, x, y, z, 1, 0, 0, 0, roundingMode, zeroAllowed,
                  infAllowed, nanAllowed);
        }
      }
    } else if (op == 1) {
      y.v = 0x0000;
      for (k = 0; k < numCases; k++) {
        z.v = cases[k].v;
        for (l = 0; l <= sgn; l++) {
          z.v ^= (l << 15);
          genCase(fptr, x, y, z, 0, 1, 0, 0, roundingMode, zeroAllowed,
                  infAllowed, nanAllowed);
        }
      }
    } else {
      for (j = 0; j < numCases; j++) {
        y.v = cases[j].v;
        for (k = 0; k < numCases; k++) {
          z.v = cases[k].v;
          for (l = 0; l <= sgn; l++) {
            y.v ^= (l << 15);
            genCase(fptr, x, y, z, 1, 1, 0, 0, roundingMode, zeroAllowed,
                    infAllowed, nanAllowed);
            z.v ^= (l << 15);

            genCase(fptr, x, y, z, 1, 1, 0, 0, roundingMode, zeroAllowed,
                    infAllowed, nanAllowed);
          }
        }
      }
    }
  }
  fclose(fptr);
}

void genWalkingOnes(char *testName, char *desc, int roundingMode,
                    int zeroAllowed, int infAllowed, int nanAllowed, int op) {
  // op = 0: only multiply; op = 1: only add; op = 2: both
  float16_t x, y, z;
  float16_t cases[100000];
  FILE *fptr;
  char fn[80];

  sprintf(fn, "work/%s.tv", testName);
  if ((fptr = fopen(fn, "w")) == 0) {
    printf("Error opening to write file %s.  Does directory exist?\n", fn);
    exit(1);
  }

  int i, j, k, l, numCases;
  numCases = 0;
  {
    float16_t temp;
    temp.v = 0x0001;

    while (temp.v != 0x0000) {
      cases[numCases] = temp;
      numCases++;
      temp.v <<= 1;
    }
  }

  z.v = 0x0000;
  for (i = 0; i < numCases; i++) {
    x.v = cases[i].v;

    if (op == 0) {
      z.v = 0x0000;
      for (j = 0; j < numCases; j++) {
        y.v = cases[j].v;
        genCase(fptr, x, y, z, 1, 0, 0, 0, roundingMode, zeroAllowed,
                infAllowed, nanAllowed);
      }
    } else if (op == 1) {
      y.v = 0x0000;
      for (k = 0; k < numCases; k++) {
        z.v = cases[k].v;
        genCase(fptr, x, y, z, 0, 1, 0, 0, roundingMode, zeroAllowed,
                infAllowed, nanAllowed);
      }
    } else {
      for (j = 0; j < numCases; j++) {
        y.v = cases[j].v;
        for (k = 0; k < numCases; k++) {
          z.v = cases[k].v;
          genCase(fptr, x, y, z, 1, 1, 0, 0, roundingMode, zeroAllowed,
                  infAllowed, nanAllowed);
        }
      }
    }
  }
  fclose(fptr);
}

int main() {
  if (system("mkdir -p work") != 0)
    exit(1);       // create work directory if it doesn't exist
  softfloatInit(); // configure softfloat modes

  // Test cases: multiplication
  genMulTests(easyExponents, easyFracts, 0, "fmul_0",
              "// Multiply with exponent of 0, significand of 1.0 and 1.1, RZ",
              0, 0, 0, 0, 0);
  genMulTests(medExponents, medFracts, 0, "fmul_1",
              "// Medium Difficulty Multiply, no Signed Y RZ", 0, 0, 0, 0, 0);
  genMulTests(medExponents, medFracts, 1, "fmul_2",
              "// Medium Difficulty Multiply, with Signed Y RZ", 0, 0, 0, 0, 0);

  // Test cases: addition
  genMulTests(easyExponents, easyFracts, 0, "fadd_0",
              "// Medium Difficulty Add, no Signed Z RZ", 0, 0, 0, 0, 1);
  genMulTests(medExponents, medFracts, 0, "fadd_1",
              "// Medium Difficulty Add, no Signed Z RZ", 0, 0, 0, 0, 1);

  genMulTests(medExponents, medFracts, 1, "fadd_2",
              "// Medium Difficulty Add, with Signed Z RZ", 0, 0, 0, 0, 1);

  // Test cases: multiply and add
  genMulTests(easyExponents, easyFracts, 0, "fma_0",
              "// Medium Difficulty Multiply and Add, no Signed Y or Z RZ", 0,
              0, 0, 0, 2);
  genMulTests(medExponents, medFracts, 0, "fma_1",
              "// Medium Difficulty Multiply and Add, no Signed Y or Z RZ", 0,
              0, 0, 0, 2);

  genMulTests(medExponents, medFracts, 1, "fma_2",
              "// Medium Difficulty Multiply and Add, with Signed Y or Z RZ", 0,
              0, 0, 0, 2);

  // Test cases: multiply and add with special cases
  genMulTests(medExponents, medFracts, 1, "fmul_special_rz",
              "// Medium Difficulty Multiply and Add, with Special Cases RZ", 0,
              1, 1, 1, 2);

  softfloat_roundingMode = softfloat_round_near_even;
  genMulTests(medExponents, medFracts, 1, "fmul_special_rne",
              "// Medium Difficulty Multiply and Add, with Special Cases RNE",
              1, 1, 1, 1, 2);

  softfloat_roundingMode = softfloat_round_min;
  genMulTests(medExponents, medFracts, 1, "fmul_special_rn",
              "// Medium Difficulty Multiply and Add, with Special Cases RN", 2,
              1, 1, 1, 2);

  softfloat_roundingMode = softfloat_round_max;
  genMulTests(medExponents, medFracts, 1, "fmul_special_rp",
              "// Medium Difficulty Multiply and Add, with Special Cases RP", 3,
              1, 1, 1, 2);

  // Walking Ones
  softfloat_roundingMode = softfloat_round_minMag;
  genWalkingOnes("fma_walk_rz", "// Walking Ones Multiply and Add, RZ", 0, 0, 0,
                 0, 2);
  softfloat_roundingMode = softfloat_round_near_even;
  genWalkingOnes("fma_walk_rne", "// Walking Ones Multiply and Add, RNE", 1, 0,
                 0, 0, 2);
  softfloat_roundingMode = softfloat_round_min;
  genWalkingOnes("fma_walk_rn", "// Walking Ones Multiply and Add, RN", 2, 0, 0,
                 0, 2);
  softfloat_roundingMode = softfloat_round_max;
  genWalkingOnes("fma_walk_rp", "// Walking Ones Multiply and Add, RP", 3, 0, 0,
                 0, 2);

  return 0;
}