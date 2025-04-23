/**********************************************************************
  * Filename:      shifter.sv
  * Description:   Shifter for FMA16
  * Author:        Vikram Krishna (vkrishna@hmc.edu)
  * Created:       April 19, 2025
  * Last Modified: April 21, 2025
**********************************************************************/

module shifter import fma16_shared::*; #(fracBits = 10, expBits = 5) (
  input logic xZero, yZero,
  input float16_t z,
  input logic [expBits+1:0] mulExp,
  output logic killProd,
  output logic stickyAligned,
  output logic [3*fracBits+3:0] alignedZ
);

  logic [fracBits+2:0] preshiftedZ; // U13.0
  logic killZ;
  logic [4*fracBits+3:0] shiftedZ, temp; // U13.31
  logic [expBits+1:0] alignmentCount; // Q7.0
  
  assign preshiftedZ = {z.sig, 2'b0};                       // Shift all the way to the left
  assign alignmentCount = mulExp - {2'b0, z.exp} + (fracBits + 2);  // Determine the alignment count
  assign killZ = (alignmentCount > 33);                                     // Check if the alignment count is too large
  assign killProd = (alignmentCount[expBits+1]) | xZero | yZero;   // Check if the product is too small

  always_comb
    if(killProd) begin
      shiftedZ = {{(fracBits+2){1'b0}}, z.sig, {(2*fracBits+1){1'b0}}};
      stickyAligned = ~(xZero | yZero);
    end else if (killZ) begin
      stickyAligned = ~z.zero;
      shiftedZ = 0;
    end
    else begin
      shiftedZ = {preshiftedZ, 31'b0} >> alignmentCount;
      stickyAligned = |shiftedZ[fracBits-1:0];
    end
  
  // Using a temporary variable to deal with linter warnings
  // assign temp = (shiftedZ >> fracBits);
  // assign alignedZ = temp[3*fracBits+3:0];

  assign alignedZ = shiftedZ[43 -: 34];
endmodule
