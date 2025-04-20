`include "shared.svh"

module fma16 (
    input  logic [15:0] x, y, z,
    input  logic        mul, add, negp, negz,
    input  logic [ 1:0] roundmode,
    output logic [15:0] result,
    output logic [ 3:0] flags
);

  float16_t xParsed, yParsed, zParsed;
  float16_t resultParsed;
  float16_t mulResult;
  logic mulResultShifted;
  logic [21:0] mulSig;

  assign xParsed = float16_t'(x);
  assign yParsed = float16_t'(y);
  assign zParsed = float16_t'(z);

  multiplier mul1 (
      .x(xParsed.sig),
      .y(yParsed.sig),
      .result(mulSig),
      .resultShifted(mulResultShifted)
  );

  logic [6:0] mulExp;
  assign mulExp = {2'b0, xParsed.exp} + {2'b0, yParsed.exp} - (mulResultShifted ? 14 : 15);
  assign mulResult.exp = mulExp[4:0];  
  assign mulResult.sign = xParsed.sign ^ yParsed.sign;
  assign resultParsed = mul ? mulResult : '0;

  logic killProd;
  logic stickyAligned;
  logic [3*10+3:0] alignedZ;
  shifter shifter1 (
      .xZero(xParsed.sig == 0),
      .yZero(yParsed.sig == 0),
      .z(zParsed),
      .mulExp(mulExp),
      .killProd(killProd),
      .stickyAligned(stickyAligned),
      .alignedZ(alignedZ) 
  );


  adder adder1 (
    .mulSign(mulResult.sign),
    .mulSig(mulSig),  
    .mulExp(mulExp),
    .alignedZ(alignedZ),
    .zExp(zParsed.exp),
    .InvA(negp),
    .KillProd(killProd),
    .stickyAligned(stickyAligned),
    .sumSign(resultParsed.sign),
    .sumExp(resultParsed.exp),
    .sumSig(resultParsed.sig)
  );

  assign result = resultParsed;
endmodule
