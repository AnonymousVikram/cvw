///////////////////////////////////////////
// mul.sv
//
// Written: David_Harris@hmc.edu 16 February 2021
// Modified: 
//
// Purpose: Integer multiplication
// 
// Documentation: RISC-V System on Chip Design
//
// A component of the CORE-V-WALLY configurable RISC-V project.
// https://github.com/openhwgroup/cvw
// 
// Copyright (C) 2021-23 Harvey Mudd College & Oklahoma State University
//
// SPDX-License-Identifier: Apache-2.0 WITH SHL-2.1
//
// Licensed under the Solderpad Hardware License v 2.1 (the “License”); you may not use this file 
// except in compliance with the License, or, at your option, the Apache License version 2.0. You 
// may obtain a copy of the License at
//
// https://solderpad.org/licenses/SHL-2.1/
//
// Unless required by applicable law or agreed to in writing, any work distributed under the 
// License is distributed on an “AS IS” BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
// either express or implied. See the License for the specific language governing permissions 
// and limitations under the License.
////////////////////////////////////////////////////////////////////////////////////////////////

module mul #(parameter XLEN) (
  input  logic                clk, reset,
  input  logic                StallM, FlushM,
  input  logic [XLEN-1:0]     ForwardedSrcAE, ForwardedSrcBE, // source A and B from after Forwarding mux
  input  logic [2:0]          Funct3E,                        // type of multiply
  output logic [XLEN*2-1:0]   ProdM                           // double-widthproduct
);

    logic [XLEN*2-1:0]  PP1M;

    logic [XLEN*2-1:0]  PP1E;
    logic Am, Bm, Pm; // MSB of A and B, and P
    logic [XLEN-2:0]  Aprime, Bprime, Pa, Pb; // A and B with MSB removed, and PA and PB
    logic [XLEN*2-1:0]  Pprime; // product of A and B with MSB removed

    always_comb begin
      Am = ForwardedSrcAE[XLEN-1];
      Bm = ForwardedSrcBE[XLEN-1];
      Pm = Am * Bm;
      Aprime = ForwardedSrcAE[XLEN-2:0];
      Bprime = ForwardedSrcBE[XLEN-2:0];
      Pa = Bm ? Aprime : 0;
      Pb = Am ? Bprime : 0;
      Pprime = Aprime * Bprime; 


      // Funct3 Key:
      // 011: unsighed/unsigned
      // 001: signed/signed
      // 010: signed/unsigned

      case (Funct3E)
        3'b001: begin
          PP1E = Pprime + {2'b00, ~Pa, {(XLEN-1){1'b0}}} + {2'b00, ~Pb, {(XLEN-1){1'b0}}} + {1'b1, Pm, {(XLEN-3){1'b0}}, 1'b1, {{(XLEN){1'b0}}}};
        end
        3'b010: begin
          PP1E = Pprime + {2'b00, Pa, {(XLEN-1){1'b0}}} + {2'b00, ~Pb, {(XLEN-1){1'b0}}} + {1'b1, ~Pm, {(XLEN-2){1'b0}}, 1'b1, {{(XLEN-1){1'b0}}}};
        end
        default: begin
          PP1E = Pprime + {2'b00, Pa, {(XLEN-1){1'b0}}} + {2'b00, Pb, {(XLEN-1){1'b0}}} + {1'b0, Pm, {(XLEN*2-2){1'b0}}};
        end
      endcase
    end

  ///////////////////////////////
  // Memory Stage: Sum partial proudcts
  //////////////////////////////

  flopenrc #(XLEN*2) PP2Reg(clk, reset, FlushM, ~StallM, PP1E, PP1M); 

  // add up partial products; this multi-input add implies CSAs and a final CPA
  assign ProdM = PP1M;
 endmodule
