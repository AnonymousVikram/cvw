module oldMultiplier (
    input logic [15:0] x,
    y,
    input logic clk,
    input logic reset,
    input logic start,
    output logic [31:0] result,
    output logic done
);

  typedef enum logic {
    WAIT,
    MULTIPLY
  } mulState_t;
  logic [31:0] acc;
  logic [3:0] count;
  logic [31:0] xreg;  // 32 bits to left shift as needed
  logic [15:0] yreg;
  mulState_t state;
  always_ff @(posedge clk or posedge reset)
    if (reset) begin
      acc   <= 0;
      count <= 0;
      xreg  <= 0;
      yreg  <= 0;
      state <= WAIT;
      done  <= 0;
    end else if (start) begin
      case (state)
        WAIT: begin
          xreg  <= x;
          yreg  <= y;
          state <= MULTIPLY;
        end
        MULTIPLY: begin
          acc   <= acc + (yreg[0] ? xreg : 0);
          count <= count + 1;
          if (count == 15) begin
            result <= acc;
            done   <= 1;
            state  <= WAIT;
          end else begin
            xreg <= xreg << 1;
            yreg <= yreg >> 1;
          end
        end
      endcase
    end

endmodule
