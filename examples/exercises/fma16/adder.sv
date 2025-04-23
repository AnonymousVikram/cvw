/**********************************************************************
  * Filename:      adder.sv
  * Description:   Adder for FMA16
  * Author:        Vikram Krishna (vkrishna@hmc.edu)
  * Created:       April 19, 2025
  * Last Modified: April 21, 2025
**********************************************************************/

module adder import fma16_shared::*; (
  input logic mulSign,
  input logic [21:0] mulSig, // U2.20
  input logic [6:0] mulExp,
  input logic [3*10+3:0] alignedZ,
  input logic [4:0] zExp,
  input logic InvA,
  input logic KillProd,
  input logic stickyAligned,
  output logic sumSign,
  output logic [6:0] sumExp,
  output logic [33:0] sumSig
);

  logic [33:0] zInv;
  logic [21:0] mulKilled;
  logic [33:0] PreSum;
  logic [33:0] NegPreSum;
  logic NegSum;

  assign zInv = InvA ? ~alignedZ : alignedZ;                                                  // invert if InvA is set
  assign mulKilled = KillProd ? 0 : mulSig;                                                   // kill the product if KillProd is set
  assign PreSum = {11'b0, mulKilled, 1'b0} + zInv + {33'b0, (~stickyAligned | KillProd)&InvA};      // align the sum
  assign NegPreSum = alignedZ + ({{11{1'b1}}, ~mulKilled, 1'b1} + {33'b0, (~stickyAligned | ~KillProd)});  // align the negated sum
  assign NegSum = PreSum[33];                                                              // check if the sum is negative

  assign sumSign = mulSign ^ NegSum;
  assign sumExp = KillProd ? {2'b0, zExp} : mulExp;
  assign sumSig = NegSum ? NegPreSum : PreSum;
endmodule
