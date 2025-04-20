module shifter #(fracBits = 10, expBits = 5) (
  input logic xZero, yZero,
  input float16_t z,
  input logic [expBits+1:0] mulExp,
  output logic killProd,
  output logic stickyAligned,
  output logic [3*fracBits+3:0] alignedZ
);

  logic [fracBits+1:0] preshiftedZ;
  logic killZ;
  logic [4*fracBits+3:0] shiftedZ, temp;
  logic [fracBits+1:0] alignmentCount;
  
  assign preshiftedZ = {2'b0, z.sig} << (fracBits+2);
  assign alignmentCount = {5'b0, mulExp} - {7'b0, z.exp} + (fracBits + 2);
  assign killZ = alignmentCount > 3*fracBits;
  assign killProd = (mulExp + fracBits+2 > z.exp) | xZero | yZero;

  always_comb
    if(killProd) begin
      shiftedZ = {z.sig, 34'b0};
      stickyAligned = ~(xZero | yZero);
    end else if (killZ) begin
      stickyAligned = z.sig != 0;
      shiftedZ = 0;
    end
    else begin
      shiftedZ = {preshiftedZ, 32'b0} >> alignmentCount;
      stickyAligned = |shiftedZ[fracBits-1:0];
    end
  assign temp = (shiftedZ >> fracBits);


  assign alignedZ = temp[3*fracBits+3:0];

endmodule
