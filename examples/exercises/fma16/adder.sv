module adder (
  input logic mulSign,
  input logic [21:0] mulSig,
  input logic [6:0] mulExp,
  input logic [3*10+3:0] alignedZ,
  input logic [4:0] zExp,
  input logic InvA,
  input logic KillProd,
  input logic stickyAligned,
  output logic sumSign,
  output logic [6:0] sumExp,
  output logic [33:0] sumSig,
)

  logic [33:0] zInv;
  logic [21:0] mulKilled;
  logic [33:0] PreSum;
  logic [33:0] NegPreSum;
  logic NegSum;

  assign zInv = InvA ? ~alignedZ : alignedZ;
  assign mulKilled = KillProd ? 0 : mulSig;
  assign PreSum = mulKilled + zInv + (~stickyAligned | KillProd)&InvA;
  assign NegPreSum = alignedZ + ~mulKilled + (~stickyAligned | ~KillProd);
  assign NegSum = PreSum[33];

  assign sumSign = mulSign ^ NegSum;
  assign sumExp = KillProd ? zExp : mulExp;
  assign sumSig = NegSum ? NegPreSum : PreSum;
endmodule
