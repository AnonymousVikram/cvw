/**********************************************************************
  * File: unpack.svh
  * Description: Unpacking unit for FMA16
  * Author: Vikram Krishna (vkrishna@hmc.edu)
  * Created: April 21, 2025
  * Last Modified: April 21, 2025
**********************************************************************/

module unpack import fma16_shared::*; (
  input logic [15:0] x,
  output float16_t xParsed
);

  logic xSign;
  logic [4:0] xExp;
  logic [9:0] xSig;

  always_comb begin
    xSign = x[15];
    xExp = x[14:10];
    xSig = x[9:0];

    // Check for special cases
    xParsed.nan = xExp == {5{1'b1}} && xSig != 0 && ~xSig[9];
    xParsed.snan = xExp == {5{1'b1}} && xSig != 0 && xSig[9];
    xParsed.inf = xExp == {5{1'b1}} && xSig == 0;
    xParsed.zero = xExp == 0 && xSig == 0;
    xParsed.subnorm = xExp == 0 && xSig != 0;

    // Configure the parsed output
    xParsed.sign = xSign;
    xParsed.exp = xParsed.subnorm ? 1 : xExp;
    xParsed.sig = (xParsed.subnorm | xParsed.zero) ? {1'b0, xSig} : {1'b1, xSig};
  end

endmodule
