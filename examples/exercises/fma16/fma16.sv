module fma16 (
    input  logic [15:0] x,
    y,
    z,
    input  logic        mul,
    add,
    negp,
    negz,
    input  logic [ 1:0] roundmode,
    output logic [15:0] result,
    output logic [ 3:0] flags
);
  typedef struct packed {
    logic sign;
    logic [4:0] exp;
    logic [9:0] sig;
  } float16_t;

  float16_t xParsed, yParsed, zParsed;
  float16_t resultParsed;
  float16_t mulResult;

  assign xParsed = float16_t'(x);
  assign yParsed = float16_t'(y);
  assign zParsed = float16_t'(z);
  // multiplier mul1(x, y, mul, mulresult);

  logic mulResultShifted;
  multiplier mul1 (
      .x(xParsed.sig),
      .y(yParsed.sig),
      .result(mulResult.sig),
      .resultShifted(mulResultShifted)
  );

  assign mulResult.exp = xParsed.exp + yParsed.exp - 15 + mulResultShifted;
  assign mulResult.sign = xParsed.sign ^ yParsed.sign;
  assign resultParsed = mul ? mulResult : '0;
  assign result = resultParsed;
endmodule
