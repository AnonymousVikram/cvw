module multiplier (
    input logic [10:0] xSig, ySig,
    output logic [21:0] result
);

  logic [21:0] partials[10:0]; // Partial products
  logic [21:0] partialsSum; // Sum of partial products

  // Generate partial products
  // Each partial product is shifted left by the index of the stage
  // and multiplied by the corresponding bit of adjY
  // The result is stored in the partials array
  genvar i;
  generate
    for (i = 0; i < 11; i = i + 1) begin : stage
      assign partials[i] = (ySig[i] ? {11'b0, xSig} : 0) << i;
    end
  endgenerate

  // Sum the partial products
  assign partialsSum = partials[0] + partials[1] + partials[2] + partials[3] + 
                  partials[4] + partials[5] + partials[6] + partials[7] + 
                  partials[8] + partials[9] + partials[10];

  assign result = partialsSum;
endmodule
