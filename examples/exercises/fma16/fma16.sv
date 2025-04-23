/**********************************************************************
  * Filename:      fma16.sv
  * Description:   Fused Multiply-Add for 16-bit floating point numbers
  * Author:        Vikram Krishna (vkrishna@hmc.edu)
  * Created:       Feburary 9, 2025
  * Last Modified: April 21, 2025
**********************************************************************/

`include "shared.svh"

module fma16 import fma16_shared::*; (
    input  logic [15:0] x, y, z,
    input  logic        mul, add, negp, negz,
    input  logic [ 1:0] roundmode,
    output logic [15:0] result,
    output logic [ 3:0] flags
);

  float16_t xParsed, yParsed, zParsed, resultParsed;

  // Multiplier Signals
  logic mulSign;
  logic [6:0] mulExp;
  logic [21:0] mulSig;

  logic mulInvalid, mulOverflow, mulInexact;

  logic mulL, mulG, mulR, mulT;

  // Shifter Signals
  logic killProd;
  logic stickyAligned;
  logic [3*10+3:0] alignedZ;

  // Adder signals
  logic sumSign;
  logic [6:0] sumExp;
  logic [3*10+3:0] sumSig;
  logic As, InvA;

  // Parsing the inputs

  unpack xUnpack (
      .x(x),
      .xParsed(xParsed)
  );
  unpack yUnpack (
      .x(y),
      .xParsed(yParsed)
  );
  unpack zUnpack (
      .x(z),
      .xParsed(zParsed)
  );

  // Multiplier
  multiplier mul1 (
      .xSig(xParsed.sig),
      .ySig(yParsed.sig),
      .result(mulSig)
  );

  assign mulExp = {2'b0, xParsed.exp} + {2'b0, yParsed.exp} - 15; // Adjust exponent for multiplication
  assign mulSign = xParsed.sign ^ yParsed.sign; // Determine the sign of the product

  assign mulInvalid = xParsed.snan | yParsed.snan | (xParsed.inf & yParsed.zero) | (yParsed.inf & xParsed.zero);
  assign mulOverflow = (mulExp > 15) | (mulExp == 15 && mulSig[21]);

  assign {mulL, mulG, mulR} = mulSig[21] ? mulSig[11:9] : mulSig[10:8]; // LSB, Guard, Round bits
  assign mulT = mulSig[21] ? |mulSig[8:0] : |mulSig[7:0]; // T bit
  assign mulInexact = mulR | mulG | mulT | mulOverflow;

  // Shifter to pre-align the z value
  shifter shifter ( // alignment shifter
      .xZero(xParsed.zero),
      .yZero(yParsed.zero),
      .z(zParsed),
      .mulExp(mulExp),
      .killProd(killProd),
      .stickyAligned(stickyAligned),
      .alignedZ(alignedZ) 
  );

  assign As = zParsed.sign ^ negz; // Determine the sign of the sum
  assign InvA = mulSign ^ As;
  // Adder to combine the results
  adder adder (
    .mulSign(xParsed.sign ^ yParsed.sign),
    .mulSig(mulSig),  
    .mulExp(mulExp),
    .alignedZ(alignedZ),
    .zExp(zParsed.exp),
    .InvA,
    .KillProd(killProd),
    .stickyAligned(stickyAligned),
    .sumSign,
    .sumExp,
    .sumSig
  );

  // Post-processing to finalize the result
  postproc postproc (
    .sumSign,
    .sumExp,
    .sumSig,
    .resultParsed
  );

  assign result = {
    resultParsed.sign,
    resultParsed.exp,
    resultParsed.sig[9:0]
  };

  // Flags
  assign flags[3] = mulInvalid | (mulOverflow & zParsed.inf);
  assign flags[2] = mulOverflow;
  assign flags[1] = 0;
  assign flags[0] = mulInexact;
endmodule
