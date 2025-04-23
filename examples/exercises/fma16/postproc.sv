/**********************************************************************
  * Filename:      postproc.sv
  * Description:   Post-processing unit for FMA16
  * Author:        Vikram Krishna (vkrishna@hmc.edu)
  * Created:       April 20, 2025
  * Last Modified: April 21, 2025
**********************************************************************/
module postproc import fma16_shared::*; (
    input logic sumSign,
    input logic [6:0] sumExp,
    input logic [33:0] sumSig,
    output float16_t resultParsed
  );


  // finding the leading 1 to renormalize
  logic [33:0] leadingOnePos;   // Position of leading 1 (one-hot encoded)
  int leadingOnePosNum; // Position of leading 1 (binary encoded)
  logic no_leading_one;         // Flag for when there are no 1s
  logic [31:0] interExp;        // Intermediate exponent value
  
  assign resultParsed.sign = sumSign;

  // Priority encoder to find the leading 1
  genvar i;
  generate
    assign leadingOnePos[33] = sumSig[33];
    for (i = 32; i >= 0; i--) begin : leading_one_search
      assign leadingOnePos[i] = sumSig[i] & ~|sumSig[33:i+1];
    end
  endgenerate

  assign no_leading_one = ~|leadingOnePos;                        // Check if there are no leading 1s
  assign leadingOnePosNum = $clog2(leadingOnePos);                // Get the position of the leading 1

  always_comb begin
   interExp = {25'b0, sumExp} + leadingOnePosNum - 21;               // Adjust exponent
   resultParsed.exp = no_leading_one ? 0 : (interExp[4:0]); // Adjust exponent for overflow
   resultParsed.sig = {1'b1, sumSig[leadingOnePosNum-1 -: 10]};

   resultParsed.nan = resultParsed.exp == {5{1'b1}} && resultParsed.sig != 0;
   resultParsed.inf = resultParsed.exp == {5{1'b1}} && resultParsed.sig == 0;
   resultParsed.zero = resultParsed.exp == 0 && resultParsed.sig == 0;
   resultParsed.subnorm = resultParsed.exp == 0 && resultParsed.sig != 0;
  end
  
endmodule
