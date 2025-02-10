module multiplier (
    input logic [9:0] x,
    y,
    output logic [9:0] result,
    output logic resultShifted
);

  logic [10:0] adjX, adjY;
  assign adjX = {1'b1, x};
  assign adjY = {1'b1, y};

  logic [21:0] partials[10:0];
  logic [21:0] partialsSum;

  genvar i;
  generate
    for (i = 0; i < 11; i = i + 1) begin : stage
      assign partials[i] = (adjY[i] ? adjX : 0) << i;
    end
  endgenerate

  assign partialsSum = partials[0] + partials[1] + partials[2] + partials[3] + 
                  partials[4] + partials[5] + partials[6] + partials[7] + 
                  partials[8] + partials[9] + partials[10];

  assign result = partialsSum[21] ? partialsSum[20:11] : partialsSum[19:10];
  assign resultShifted = partialsSum[21];

endmodule
