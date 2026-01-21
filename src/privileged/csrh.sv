///////////////////////////////////////////
// csrh.sv
//
// Written: nchulani@hmc.edu, vkrishna@hmc.edu, jgong@hmc.edu 11 November 2025
// Purpose: Hypervisor-Mode Control and Status Registers
//          See RISC-V Privileged Mode Specification (Hypervisor Extension)
//
// Documentation: RISC-V System on Chip Design
//
// A component of the CORE-V-WALLY configurable RISC-V project.
// https://github.com/openhwgroup/cvw
//
// Copyright (C) 2021-25 Harvey Mudd College & Oklahoma State University
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

module csrh import cvw::*;  #(parameter cvw_t P) (
  input  logic              clk, reset,
  input  logic              CSRHWriteM,       // High if operation is a write
  input  logic [11:0]       CSRAdrM,
  input  logic [P.XLEN-1:0] CSRWriteValM,
  input  logic [1:0]        PrivilegeModeW,   // Current privilege mode (U, S, M)
  input  logic              NextVirtModeM,    // Next V-mode bit (for hstatus.SPV)
  input  logic              VirtModeW,        // Virtualization mode (VS/VU)
  input  logic [11:0]       MIP_REGW,         // mip register for HIP calculation

  input  logic              HSTrapM,          // Trap occurred in HS-mode
  input  logic              PrivReturnHSM,    // Privilege return (sret) from HS-mode
  input  logic [P.XLEN-1:0] NextHtvalM,       // Value for htval on trap
  input  logic [P.XLEN-1:0] NextMtinstM,      // Value for mtinst on trap
  input  logic [P.XLEN-1:0] NextHtinstM,      // Value for htinst on trap
  input  logic [P.XLEN-1:0] NextMtval2M,      // Value for mtval2 on trap

  output logic [P.XLEN-1:0] CSRHReadValM,
  output logic              IllegalCSRHAccessM
);

  logic [P.XLEN-1:0] MTINST_REGW;
  logic [P.XlEN-1:0] MTVAL2_REGW;
  logic [P.XLEN-1:0] HSTATUS_REGW;
  logic [P.XLEN-1:0] VSTATUS_REGW;
  logic [63:0] HEDELEG_REGW;
  logic [P.XLEN-1:0] HIDELEG_REGW;
  logic [P.XLEN-1:0] HIE_REGW;
  logic [P.XLEN-1:0] VSIE_REGW;
  logic [63:0] HTIMEDELTA_REGW;
  logic [31:0]       HCOUNTEREN_REGW;
  logic [P.XLEN-1:0] HGEIE_REGW;
  logic [63:0]       HENVCFG_REGW;
  logic [P.XLEN-1:0] HTVAL_REGW;
  logic [P.XLEN-1:0] VSTVAL_REGW;
  logic [P.XLEN-1:0] HIP_REGW;
  logic [P.XLEN-1:0] VSIP_REGW;
  logic [11:0]       HVIP_REGW; // 12 bits due to top bits being 0
  logic [P.XLEN-1:0] HTINST_REGW;
  logic [P.XLEN-1:0] HGATP_REGW;
  logic [P.XLEN-1:0] HGEIP_REGW;
  logic [P.XLEN-1:0] VSTVEC_REGW;
  logic [P.XLEN-1:0] VSSCRATCH_REGW;
  logic [P.XLEN-1:0] VSEPC_REGW;
  logic [P.XLEN-1:0] VSCAUSE_REGW;
  logic [P.XLEN-1:0] VSATP_REGW;
  logic [63:0] VSTIMECMP_REGW;

  // Hypervisor CSR Addresses
  localparam MTINST     = 12'h34A;
  localparam MTVAL2     = 12'h34B;
  localparam HSTATUS    = 12'h600;
  localparam VSSTATUS   = 12'h200;
  localparam HEDELEG    = 12'h602;
  localparam HEDELEGH    = 12'h612;
  localparam HIDELEG    = 12'h603;
  localparam HIE        = 12'h604;
  localparam VSIE       = 12'h204;
  localparam HTIMEDELTA = 12'h605;
  localparam HTIMEDELTAH = 12'h615;
  localparam HCOUNTEREN = 12'h606;
  localparam HGEIE      = 12'h607;
  localparam HENVCFG    = 12'h60A;
  localparam HENVCFGH   = 12'h61A;
  localparam HTVAL      = 12'h643;
  localparam VSTVAL    = 12'h243;
  localparam HIP        = 12'h644;
  localparam VSIP        = 12'h244;
  localparam HVIP       = 12'h645;
  localparam HTINST     = 12'h64A;
  localparam HGATP      = 12'h680;
  localparam HGEIP      = 12'hE12;
  localparam VSTVEC     = 12'h205;
  localparam VSSCRATCH  = 12'h240;
  localparam VSEPC      = 12'h241;
  localparam VSCAUSE    = 12'h242;
  localparam VSATP      = 12'h280;
  localparam VSTIMECMP  = 12'h24D;
  localparam VSTIMECMPH = 12'h25D;

  // Write Enables for CSR instructions
  logic WriteMTINSTM;
  logic WriteMTVAL2M;
  logic WriteHSTATUSM, WriteVSSTATUS;
  logic WriteHEDELEGM, WriteHEDELEGHM;
  logic WriteHIDELEGM;
  logic WriteHIEM, WriteVSIEM;
  logic WriteHTIMEDELTAM, WriteHTIMEDELTAHM;
  logic WriteHCOUNTERENM;
  logic WriteHGEIEM;
  logic WriteHENVCFGM, WriteHENVCFGHM;
  logic WriteHTVALM, WriteVSTVALM;
  logic WriteHIPM, WriteVSIPM;
  logic WriteHVIPM;
  logic WriteHTINSTM;
  logic WriteHGATPM;
  logic WriteHGEIPM;
  logic WriteVSTVECM;
  logic WriteVSSCRATCHM;
  logic WriteVSEPCM;
  logic WriteVSCAUSEM;
  logic WriteVSATPM;
  logic WriteVSTIMECMPM, WriteVSTIMECMPHM;

  // Next Value Muxes
  logic [P.XLEN-1:0] NextHSTATUS;
  logic [P.XLEN-1:0] NextHTVAL;
  logic [P.XLEN-1:0] NextHTINST;

  // CSR Write Validation Intermediates
  logic LegalHAccessM;
  logic ReadOnlyCSR;
  logic ValidWrite;

  // H-CSRs are accessible in M-Mode or HS-Mode.
  // HS-Mode is S-Mode when VirtModeW is 0.
  // Access is ILLEGAL in U-Mode (U/VU) and VS-Mode (S-Mode when VirtModeW=1).
  assign LegalHAccessM = (PrivilegeModeW == P.M_MODE) |
                        ((PrivilegeModeW == P.S_MODE) & ~VirtModeW);

  assign ReadOnlyCSR = (CSRAdrM == HIP);

  assign ValidWrite = CSRHWriteM & LegalHAccessM & ~ReadOnlyCSR;

  // Write enables for each CSR (from CSR instruction)
  assign WriteMTINSTM     = ValidWrite & (CSRAdrM == MTINST);
  assign WriteMTVAL2M     = ValidWrite & (CSRAdrM == MTVAL2);
  assign WriteHSTATUSM    = ValidWrite & (CSRAdrM == HSTATUS);
  assign WriteVSSTATUS    = ValidWrite & (CSRAdrM == VSSTATUS);
  assign WriteHEDELEGM    = ValidWrite & (CSRAdrM == HEDELEG);
  assign WriteHEDELEGHM   = (P.XLEN == 32) & (ValidWrite & (CSRAdrM == HEDELEGH));
  assign WriteHIDELEGM    = ValidWrite & (CSRAdrM == HIDELEG);
  assign WriteHIEM        = ValidWrite & (CSRAdrM == HIE);
  assign WriteVSIEM       = ValidWrite & (CSRAdrM == VSIE);
  assign WriteHTIMEDELTAM = ValidWrite & (CSRAdrM == HTIMEDELTA);
  assign WriteHTIMEDELTAHM = (P.XLEN == 32) & (ValidWrite & (CSRAdrM == HTIMEDELTAH));
  assign WriteHCOUNTERENM = ValidWrite & (CSRAdrM == HCOUNTEREN);
  assign WriteHGEIEM      = ValidWrite & (CSRAdrM == HGEIE);
  assign WriteHENVCFGM    = ValidWrite & (CSRAdrM == HENVCFG);
  assign WriteHENVCFGHM   = (P.XLEN == 32) & (ValidWrite & (CSRAdrM == HENVCFGH));
  assign WriteHTVALM      = ValidWrite & (CSRAdrM == HTVAL);
  assign WriteVSTVALM     = ValidWrite & (CSRAdrM == VSTVAL);
  assign WriteHIPM        = ValidWrite & (CSRAdrM == HIP);
  assign WriteVSIPM       = ValidWrite & (CSRAdrM == VSIP);
  assign WriteHVIPM       = ValidWrite & (CSRAdrM == HVIP);
  assign WriteHTINSTM     = ValidWrite & (CSRAdrM == HTINST);
  assign WriteHGATPM      = ValidWrite & (CSRAdrM == HGATP);
  assign WriteHGEIPM      = ValidWrite & (CSRAdrM == HGEIP);
  assign WriteVSTVECM     = ValidWrite & (CSRAdrM == VSTVEC);
  assign WriteVSSCRATCHM  = ValidWrite & (CSRAdrM == VSSCRATCH);
  assign WriteVSEPCM      = ValidWrite & (CSRAdrM == VSEPC);
  assign WriteVSCAUSEM    = ValidWrite & (CSRAdrM == VSCAUSE);
  assign WriteVSATPM      = ValidWrite & (CSRAdrM == VSATP);
  assign WriteVSTIMECMPM  = ValidWrite & (CSRAdrM == VSTIMECMP);
  assign WriteVSTIMECMPHM = (P.XLEN == 32) & (ValidWrite & (CSRAdrM == VSTIMECMPH));


  // MTINST
  flopenr #(P.XLEN) MTINSTreg(clk, reset, WriteMTINSTM, NextMtinstM, MTINST_REGW);

  // MTVAL2
  flopenr #(P.XLEN) MTVAL2reg(clk, reset, WriteMTVAL2M, NextMtval2M, MTVAL2_REGW);


  // HSTATUS
  // This register is written by CSR instructions and by hardware on sret
  // Three-way mux: CSR write -> CSRWriteValM, sret -> update SPV bit (bit 7), otherwise -> hold
  assign NextHSTATUS = WriteHSTATUSM ? CSRWriteValM :
                       PrivReturnHSM ? {HSTATUS_REGW[P.XLEN-1:8], NextVirtModeM, HSTATUS_REGW[6:0]} :
                       HSTATUS_REGW;
  flopr #(P.XLEN) HSTATUSreg(clk, reset, NextHSTATUS, HSTATUS_REGW);

  // VSSTATUS TODO:Neil implement logic from SSTATUS (Found in csrsr.sv)

  // Exception and Interrupt Delegation Registers TODO: Neil implement
  // read-only zero bits (see ISA 15.2.2)
  flopenr #(P.XLEN) HEDELEGreg(clk, reset, WriteHEDELEGM, CSRWriteValM, HEDELEG_REGW);
  flopenr #(P.XLEN) HIDELEGreg(clk, reset, WriteHIDELEGM, CSRWriteValM, HIDELEG_REGW);

  // Interrupt Enable / Pending
  flopenr #(P.XLEN) HIEreg(clk, reset, WriteHIEM, CSRWriteValM, HIE_REGW);
  flopenr #(12)     HVIPreg(clk, reset, WriteHVIPM, CSRWriteValM[11:0], HVIP_REGW);
  flopenr #(P.XLEN) HGEIEreg(clk, reset, WriteHGEIEM, CSRWriteValM, HGEIE_REGW);

  // HTVAL: Written by CSR instructions and by hardware on traps
  assign NextHTVAL = HSTrapM ? NextHtvalM : CSRWriteValM;
  flopenr #(P.XLEN) HTVALreg(clk, reset, (WriteHTVALM | HSTrapM), NextHTVAL, HTVAL_REGW);

  // HTINST: Written by CSR instructions and by hardware on traps
  assign NextHTINST = HSTrapM ? NextHtinstMinstM : CSRWriteValM;
  flopenr #(P.XLEN) HTINSTreg(clk, reset, (WriteHTINSTM | HSTrapM), NextHTINST, HTINST_REGW);

  // Address Translation
  flopenr #(P.XLEN) HGATPreg(clk, reset, WriteHGATPM, CSRWriteValM, HGATP_REGW);

  // Configuration & Timers
  flopenr #(32) HCOUNTERENreg(clk, reset, WriteHCOUNTERENM, CSRWriteValM[31:0], HCOUNTEREN_REGW);
  if (P.XLEN == 64) begin : henvcfg_regs_64
    flopenr #(P.XLEN) HENVCFGreg(clk, reset, WriteHENVCFGM, {32'b0, CSRWriteValM[31:0]}, HENVCFG_REGW);
  end else begin : henvcfg_regs_32
    flopenr #(P.XLEN) HENVCFGreg(clk, reset, WriteHENVCFGM, CSRWriteValM, HENVCFG_REGW[31:0]);
    flopenr #(P.XLEN) HENVCFGHreg(clk, reset, WriteHENVCFGHM, CSRWriteValM, HENVCFG_REGW[63:32]);
  end
  if (P.XLEN == 64) begin : htimedelta_regs_64
    flopenr #(P.XLEN) HTIMEDELTAreg(clk, reset, WriteHTIMEDELTAM, CSRWriteValM, HTIMEDELTA_REGW);
  end else begin : htimedelta_regs_32
    flopenr #(P.XLEN) HTIMEDELTAreg(clk, reset, WriteHTIMEDELTAM, CSRWriteValM, HTIMEDELTA_REGW[31:0]);
    flopenr #(P.XLEN) HTIMEDELTAHreg(clk, reset, WriteHTIMEDELTAHM, CSRWriteValM, HTIMEDELTA_REGW[63:32]);
  end
  flopenr #(P.XLEN) HGEIPreg(clk, reset, WriteHGEIPM, CSRWriteValM, HGEIP_REGW);


  // CSR Read and Illegal Access Logic
  always_comb begin : csrrh
    CSRHReadValM = '0;
    IllegalCSRHAccessM = 1'b0;

    if (~LegalHAccessM) begin : illegalaccess
      IllegalCSRHAccessM = 1'b1;
    end else begin : legalaccess_mux
      case (CSRAdrM)
        HSTATUS:    CSRHReadValM = HSTATUS_REGW;
        HEDELEG:    CSRHReadValM = HEDELEG_REGW;
        HIDELEG:    CSRHReadValM = HIDELEG_REGW;
        HIE:        CSRHReadValM = HIE_REGW;
        HTIMEDELTA: CSRHReadValM = HTIMEDELTA_REGW[P.XLEN-1:0];
        HTIMEDELTAH: if (P.XLEN == 32)
                       CSRHReadValM = HTIMEDELTA_REGW[63:32];
                     else begin
                       CSRHReadValM = '0;
                       IllegalCSRHAccessM = 1'b1;
                     end
        HCOUNTEREN: CSRHReadValM = {{P.XLEN-32){1'b0}}, HCOUNTEREN_REGW};
        HGEIE:      CSRHReadValM = HGEIE_REGW;
        HENVCFG:    CSRHReadValM = HENVCFG_REGW[P.XLEN-1:0];
        HENVCFGH:   if (P.XLEN == 32)
                      CSRHReadValM = HENVCFG_REGW[63:32];
                    else begin
                      CSRHReadValM = '0;
                      IllegalCSRHAccessM = 1'b1;
                    end
        HTVAL:      CSRHReadValM = HTVAL_REGW;
        HIP:        CSRHReadValM = {{(P.XLEN-12){1'b0}}, (HVIP_REGW | MIP_REGW)}; // Read-only derived value
        HVIP:       CSRHReadValM = {{(P.XLEN-12){1'b0}}, HVIP_REGW};
        HTINST:     CSRHReadValM = HTINST_REGW;
        HGATP:      CSRHReadValM = HGATP_REGW;
        HGEIP:      CSRHReadValM = HGEIP_REGW;
        default:    IllegalCSRHAccessM = 1'b1;
      endcase

      if (CSRHWriteM && ReadOnlyCSR) begin
        IllegalCSRHAccessM = 1'b1;
      end
    end
  end

endmodule
