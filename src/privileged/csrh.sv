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
  input  logic              VirtModeW,        // Virtualization mode (VS/VU)
  input  logic [11:0]       MIP_REGW,         // mip register for HIP calculation

  input  logic              HSTrapM,          // Trap occurred in HS-mode
  input  logic              VSTrapM,          // Trap occurred in VS-mode
  input  logic              PrivReturnHSM,    // Privilege return (sret) from HS-mode
  input  logic              PrivReturnVSM,    // Privilege return (sret) from VS-mode
  input  logic [P.XLEN-1:0] NextEPCM,         // EPC value for trap/return
  input  logic [4:0]        NextCauseM,       // Exception/interrupt cause
  input  logic [P.XLEN-1:0] NextMtvalM,       // Value for {v,s,}tval on trap
  input  logic [P.XLEN-1:0] NextHtvalM,       // Value for htval on trap
  input  logic [P.XLEN-1:0] NextMtinstM,      // Value for mtinst on trap
  input  logic [P.XLEN-1:0] NextHtinstM,      // Value for htinst on trap
  input  logic [P.XLEN-1:0] NextMtval2M,      // Value for mtval2 on trap

  output logic [P.XLEN-1:0] CSRHReadValM,
  output logic              IllegalCSRHAccessM,
  output logic              HSTATUS_SPV,
  output logic [63:0]       HEDELEG_REGW,
  output logic [11:0]       HIDELEG_REGW,
  output logic [P.XLEN-1:0] VSTVEC_REGW,
  output logic [P.XLEN-1:0] VSEPC_REGW
);

  logic [P.XLEN-1:0] MTINST_REGW;
  logic [P.XLEN-1:0] MTVAL2_REGW;
  logic [P.XLEN-1:0] HSTATUS_REGW;
  logic [P.XLEN-1:0] VSSTATUS_REGW;
  logic              VSSTATUS_SD, VSSTATUS_MXR, VSSTATUS_SUM;
  logic              VSSTATUS_MXR_INT, VSSTATUS_SUM_INT;
  logic              VSSTATUS_SPIE, VSSTATUS_SIE, VSSTATUS_SPP, VSSTATUS_UBE;
  logic [1:0]        VSSTATUS_FS_INT, VSSTATUS_FS, VSSTATUS_XS, VSSTATUS_UXL;
  logic [P.XLEN-1:0] HIE_REGW;
  logic [11:0]       VSIE_REGW;
  logic [63:0] HTIMEDELTA_REGW;
  logic [31:0]       HCOUNTEREN_REGW;
  logic [P.XLEN-1:0] HGEIE_REGW;
  logic [63:0]       HENVCFG_REGW;
  logic [P.XLEN-1:0] HTVAL_REGW;
  logic [P.XLEN-1:0] VSTVAL_REGW;
  logic [P.XLEN-1:0] HIP_REGW;
  logic [11:0]       VSIP_REGW;
  logic [11:0]       HVIP_REGW; // 12 bits due to top bits being 0
  logic [P.XLEN-1:0] HTINST_REGW;
  logic [P.XLEN-1:0] HGATP_REGW;
  logic [P.XLEN-1:0] HGEIP_REGW;
  logic [P.XLEN-1:0] VSSCRATCH_REGW;
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
  localparam [63:0] HEDELEG_MASK = 64'h0000_0000_0000_FFFF;
  localparam [11:0] HIDELEG_MASK = 12'hFFF;

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
  logic [63:0]       NextHEDELEG;
  logic [11:0]       NextHIDELEG;
  logic [P.XLEN-1:0] VSTVECWriteValM;

  // CSR Write Validation Intermediates
  logic LegalHAccessM;
  logic LegalVSAccessM;
  logic IsHCSR, IsVSCSR;
  logic ReadOnlyCSR;
  logic ValidHWrite, ValidVSWrite;

  // H-CSRs are accessible in M-Mode or HS-Mode.
  // VS-CSRs are accessible in M-Mode, HS-Mode, and VS-Mode.
  // Access is ILLEGAL in U-Mode (U/VU), and H-CSRs are illegal in VS-Mode.
  assign LegalHAccessM = (PrivilegeModeW == P.M_MODE) |
                        ((PrivilegeModeW == P.S_MODE) & ~VirtModeW);
  assign LegalVSAccessM = (PrivilegeModeW == P.M_MODE) |
                          (PrivilegeModeW == P.S_MODE);

  assign IsHCSR = (CSRAdrM == MTINST) | (CSRAdrM == MTVAL2) | (CSRAdrM == HSTATUS) |
                  (CSRAdrM == HEDELEG) | (CSRAdrM == HEDELEGH) | (CSRAdrM == HIDELEG) |
                  (CSRAdrM == HIE) | (CSRAdrM == HTIMEDELTA) | (CSRAdrM == HTIMEDELTAH) |
                  (CSRAdrM == HCOUNTEREN) | (CSRAdrM == HGEIE) | (CSRAdrM == HENVCFG) |
                  (CSRAdrM == HENVCFGH) | (CSRAdrM == HTVAL) | (CSRAdrM == HIP) |
                  (CSRAdrM == HVIP) | (CSRAdrM == HTINST) | (CSRAdrM == HGATP) |
                  (CSRAdrM == HGEIP);
  assign IsVSCSR = (CSRAdrM == VSSTATUS) | (CSRAdrM == VSIE) | (CSRAdrM == VSTVEC) |
                   (CSRAdrM == VSSCRATCH) | (CSRAdrM == VSEPC) | (CSRAdrM == VSCAUSE) |
                   (CSRAdrM == VSTVAL) | (CSRAdrM == VSIP) | (CSRAdrM == VSATP) |
                   (CSRAdrM == VSTIMECMP) | (CSRAdrM == VSTIMECMPH);

  assign ReadOnlyCSR = (CSRAdrM == HIP);

  assign ValidHWrite  = CSRHWriteM & LegalHAccessM & IsHCSR & ~ReadOnlyCSR;
  assign ValidVSWrite = CSRHWriteM & LegalVSAccessM & IsVSCSR;

  // Write enables for each CSR (from CSR instruction)
  assign WriteMTINSTM     = ValidHWrite & (CSRAdrM == MTINST);
  assign WriteMTVAL2M     = ValidHWrite & (CSRAdrM == MTVAL2);
  assign WriteHSTATUSM    = ValidHWrite & (CSRAdrM == HSTATUS);
  assign WriteVSSTATUS    = ValidVSWrite & (CSRAdrM == VSSTATUS);
  assign WriteHEDELEGM    = ValidHWrite & (CSRAdrM == HEDELEG);
  assign WriteHEDELEGHM   = (P.XLEN == 32) & (ValidHWrite & (CSRAdrM == HEDELEGH));
  assign WriteHIDELEGM    = ValidHWrite & (CSRAdrM == HIDELEG);
  assign WriteHIEM        = ValidHWrite & (CSRAdrM == HIE);
  assign WriteVSIEM       = ValidVSWrite & (CSRAdrM == VSIE);
  assign WriteHTIMEDELTAM = ValidHWrite & (CSRAdrM == HTIMEDELTA);
  assign WriteHTIMEDELTAHM = (P.XLEN == 32) & (ValidHWrite & (CSRAdrM == HTIMEDELTAH));
  assign WriteHCOUNTERENM = ValidHWrite & (CSRAdrM == HCOUNTEREN);
  assign WriteHGEIEM      = ValidHWrite & (CSRAdrM == HGEIE);
  assign WriteHENVCFGM    = ValidHWrite & (CSRAdrM == HENVCFG);
  assign WriteHENVCFGHM   = (P.XLEN == 32) & (ValidHWrite & (CSRAdrM == HENVCFGH));
  assign WriteHTVALM      = ValidHWrite & (CSRAdrM == HTVAL);
  assign WriteVSTVALM     = ValidVSWrite & (CSRAdrM == VSTVAL);
  assign WriteHIPM        = ValidHWrite & (CSRAdrM == HIP);
  assign WriteVSIPM       = ValidVSWrite & (CSRAdrM == VSIP);
  assign WriteHVIPM       = ValidHWrite & (CSRAdrM == HVIP);
  assign WriteHTINSTM     = ValidHWrite & (CSRAdrM == HTINST);
  assign WriteHGATPM      = ValidHWrite & (CSRAdrM == HGATP);
  assign WriteHGEIPM      = ValidHWrite & (CSRAdrM == HGEIP);
  assign WriteVSTVECM     = ValidVSWrite & (CSRAdrM == VSTVEC);
  assign WriteVSSCRATCHM  = ValidVSWrite & (CSRAdrM == VSSCRATCH);
  assign WriteVSEPCM      = ValidVSWrite & (CSRAdrM == VSEPC);
  assign WriteVSCAUSEM    = ValidVSWrite & (CSRAdrM == VSCAUSE);
  assign WriteVSATPM      = ValidVSWrite & (CSRAdrM == VSATP) & P.VIRTMEM_SUPPORTED;
  assign WriteVSTIMECMPM  = ValidVSWrite & (CSRAdrM == VSTIMECMP) & P.SSTC_SUPPORTED;
  assign WriteVSTIMECMPHM = (P.XLEN == 32) & P.SSTC_SUPPORTED & (ValidVSWrite & (CSRAdrM == VSTIMECMPH));


  // MTINST
  flopenr #(P.XLEN) MTINSTreg(clk, reset, WriteMTINSTM, NextMtinstM, MTINST_REGW);

  // MTVAL2
  flopenr #(P.XLEN) MTVAL2reg(clk, reset, WriteMTVAL2M, NextMtval2M, MTVAL2_REGW);


  // HSTATUS
  // This register is written by CSR instructions and by hardware on traps/returns
  // SPV captures the prior V on HS traps and clears on HS sret
  assign NextHSTATUS = HSTrapM       ? {HSTATUS_REGW[P.XLEN-1:8], VirtModeW, HSTATUS_REGW[6:0]} :
                       PrivReturnHSM ? {HSTATUS_REGW[P.XLEN-1:8], 1'b0,      HSTATUS_REGW[6:0]} :
                       WriteHSTATUSM ? CSRWriteValM :
                       HSTATUS_REGW;
  flopr #(P.XLEN) HSTATUSreg(clk, reset, NextHSTATUS, HSTATUS_REGW);
  assign HSTATUS_SPV = HSTATUS_REGW[7];

  // VSSTATUS
  // Guest-visible SSTATUS state, updated on VS traps/returns or CSR writes
  assign VSSTATUS_MXR = P.S_SUPPORTED & VSSTATUS_MXR_INT;
  assign VSSTATUS_SUM = P.S_SUPPORTED & P.VIRTMEM_SUPPORTED & VSSTATUS_SUM_INT;
  assign VSSTATUS_FS  = P.F_SUPPORTED ? VSSTATUS_FS_INT : 2'b00;
  assign VSSTATUS_XS  = 2'b00;
  assign VSSTATUS_SD  = (VSSTATUS_FS == 2'b11) | (VSSTATUS_XS == 2'b11);
  assign VSSTATUS_UXL = P.U_SUPPORTED ? 2'b10 : 2'b00;

  if (P.XLEN == 64) begin : vsstatus64
    assign VSSTATUS_REGW = {VSSTATUS_SD, 29'b0, VSSTATUS_UXL, 12'b0,
                            VSSTATUS_MXR, VSSTATUS_SUM, 1'b0,
                            VSSTATUS_XS, VSSTATUS_FS, 4'b0,
                            VSSTATUS_SPP, 1'b0, VSSTATUS_UBE, VSSTATUS_SPIE,
                            3'b0, VSSTATUS_SIE, 1'b0};
  end else begin : vsstatus32
    assign VSSTATUS_REGW = {VSSTATUS_SD, 11'b0,
                            VSSTATUS_MXR, VSSTATUS_SUM, 1'b0,
                            VSSTATUS_XS, VSSTATUS_FS, 4'b0,
                            VSSTATUS_SPP, 1'b0, VSSTATUS_UBE, VSSTATUS_SPIE,
                            3'b0, VSSTATUS_SIE, 1'b0};
  end

  always_ff @(posedge clk)
    if (reset) begin
      VSSTATUS_MXR_INT <= 1'b0;
      VSSTATUS_SUM_INT <= 1'b0;
      VSSTATUS_FS_INT  <= 2'b00;
      VSSTATUS_SPP     <= 1'b0;
      VSSTATUS_SPIE    <= 1'b0;
      VSSTATUS_SIE     <= 1'b0;
      VSSTATUS_UBE     <= 1'b0;
    end else if (VSTrapM) begin
      VSSTATUS_SPIE <= VSSTATUS_SIE;
      VSSTATUS_SIE  <= 1'b0;
      VSSTATUS_SPP  <= PrivilegeModeW[0];
    end else if (PrivReturnVSM) begin
      VSSTATUS_SIE  <= VSSTATUS_SPIE;
      VSSTATUS_SPIE <= 1'b1;
      VSSTATUS_SPP  <= 1'b0;
    end else if (WriteVSSTATUS) begin
      VSSTATUS_MXR_INT <= P.S_SUPPORTED & CSRWriteValM[19];
      VSSTATUS_SUM_INT <= P.VIRTMEM_SUPPORTED & CSRWriteValM[18];
      VSSTATUS_FS_INT  <= CSRWriteValM[14:13];
      VSSTATUS_SPP     <= P.S_SUPPORTED & CSRWriteValM[8];
      VSSTATUS_SPIE    <= P.S_SUPPORTED & CSRWriteValM[5];
      VSSTATUS_SIE     <= P.S_SUPPORTED & CSRWriteValM[1];
      VSSTATUS_UBE     <= P.U_SUPPORTED & P.BIGENDIAN_SUPPORTED & CSRWriteValM[6];
    end

  // Exception and Interrupt Delegation Registers
  // Mask off read-only zero bits (see ISA 15.2.2)
  always_comb begin
    NextHEDELEG = HEDELEG_REGW;
    if (WriteHEDELEGM)  NextHEDELEG[31:0]  = CSRWriteValM[31:0] & HEDELEG_MASK[31:0];
    if (WriteHEDELEGHM) NextHEDELEG[63:32] = CSRWriteValM[31:0] & HEDELEG_MASK[63:32];
  end
  flopenr #(64) HEDELEGreg(clk, reset, (WriteHEDELEGM | WriteHEDELEGHM), NextHEDELEG, HEDELEG_REGW);

  assign NextHIDELEG = WriteHIDELEGM ? (CSRWriteValM[11:0] & HIDELEG_MASK) : HIDELEG_REGW;
  flopenr #(12) HIDELEGreg(clk, reset, WriteHIDELEGM, NextHIDELEG, HIDELEG_REGW);

  // Interrupt Enable / Pending
  flopenr #(P.XLEN) HIEreg(clk, reset, WriteHIEM, CSRWriteValM, HIE_REGW);
  flopenr #(12)     HVIPreg(clk, reset, WriteHVIPM, CSRWriteValM[11:0], HVIP_REGW);
  flopenr #(P.XLEN) HGEIEreg(clk, reset, WriteHGEIEM, CSRWriteValM, HGEIE_REGW);
  flopenr #(12)     VSIEreg(clk, reset, WriteVSIEM, CSRWriteValM[11:0], VSIE_REGW);
  flopenr #(12)     VSIPreg(clk, reset, WriteVSIPM, CSRWriteValM[11:0], VSIP_REGW);

  // HTVAL: Written by CSR instructions and by hardware on traps
  assign NextHTVAL = HSTrapM ? NextHtvalM : CSRWriteValM;
  flopenr #(P.XLEN) HTVALreg(clk, reset, (WriteHTVALM | HSTrapM), NextHTVAL, HTVAL_REGW);

  // HTINST: Written by CSR instructions and by hardware on traps
  assign NextHTINST = HSTrapM ? NextHtinstM : CSRWriteValM;
  flopenr #(P.XLEN) HTINSTreg(clk, reset, (WriteHTINSTM | HSTrapM), NextHTINST, HTINST_REGW);

  // VS CSRs: Guest-visible S-mode state
  assign VSTVECWriteValM = CSRWriteValM[0] ? {CSRWriteValM[P.XLEN-1:6], 6'b000001} :
                                              {CSRWriteValM[P.XLEN-1:2], 2'b00};
  flopenr #(P.XLEN) VSTVECreg(clk, reset, WriteVSTVECM, VSTVECWriteValM, VSTVEC_REGW);
  flopenr #(P.XLEN) VSSCRATCHreg(clk, reset, WriteVSSCRATCHM, CSRWriteValM, VSSCRATCH_REGW);
  flopenr #(P.XLEN) VSEPCreg(clk, reset, (VSTrapM | WriteVSEPCM), NextEPCM, VSEPC_REGW);
  flopenr #(P.XLEN) VSCAUSEreg(clk, reset, (VSTrapM | WriteVSCAUSEM),
                              {NextCauseM[4], {(P.XLEN-5){1'b0}}, NextCauseM[3:0]}, VSCAUSE_REGW);
  flopenr #(P.XLEN) VSTVALreg(clk, reset, (VSTrapM | WriteVSTVALM), NextMtvalM, VSTVAL_REGW);
  if (P.VIRTMEM_SUPPORTED)
    flopenr #(P.XLEN) VSATPreg(clk, reset, WriteVSATPM, CSRWriteValM, VSATP_REGW);
  else
    assign VSATP_REGW = '0;

  if (P.SSTC_SUPPORTED) begin : vstc
    if (P.XLEN == 64) begin : vstc64
      flopenr #(P.XLEN) VSTIMECMPreg(clk, reset, WriteVSTIMECMPM, CSRWriteValM, VSTIMECMP_REGW);
    end else begin : vstc32
      flopenr #(P.XLEN) VSTIMECMPreg(clk, reset, WriteVSTIMECMPM, CSRWriteValM, VSTIMECMP_REGW[31:0]);
      flopenr #(P.XLEN) VSTIMECMPHreg(clk, reset, WriteVSTIMECMPHM, CSRWriteValM, VSTIMECMP_REGW[63:32]);
    end
  end else assign VSTIMECMP_REGW = '0;

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

    case (CSRAdrM)
      HSTATUS:    if (LegalHAccessM) CSRHReadValM = HSTATUS_REGW; else IllegalCSRHAccessM = 1'b1;
      HEDELEG:    if (LegalHAccessM) CSRHReadValM = HEDELEG_REGW[P.XLEN-1:0]; else IllegalCSRHAccessM = 1'b1;
      HEDELEGH:   if (LegalHAccessM & (P.XLEN == 32))
                    CSRHReadValM = HEDELEG_REGW[63:32];
                  else
                    IllegalCSRHAccessM = 1'b1;
      HIDELEG:    if (LegalHAccessM) CSRHReadValM = {{(P.XLEN-12){1'b0}}, HIDELEG_REGW}; else IllegalCSRHAccessM = 1'b1;
      HIE:        if (LegalHAccessM) CSRHReadValM = HIE_REGW; else IllegalCSRHAccessM = 1'b1;
      HTIMEDELTA: if (LegalHAccessM) CSRHReadValM = HTIMEDELTA_REGW[P.XLEN-1:0]; else IllegalCSRHAccessM = 1'b1;
      HTIMEDELTAH: if (LegalHAccessM & (P.XLEN == 32))
                     CSRHReadValM = HTIMEDELTA_REGW[63:32];
                   else
                     IllegalCSRHAccessM = 1'b1;
      HCOUNTEREN: if (LegalHAccessM) CSRHReadValM = {{(P.XLEN-32){1'b0}}, HCOUNTEREN_REGW}; else IllegalCSRHAccessM = 1'b1;
      HGEIE:      if (LegalHAccessM) CSRHReadValM = HGEIE_REGW; else IllegalCSRHAccessM = 1'b1;
      HENVCFG:    if (LegalHAccessM) CSRHReadValM = HENVCFG_REGW[P.XLEN-1:0]; else IllegalCSRHAccessM = 1'b1;
      HENVCFGH:   if (LegalHAccessM & (P.XLEN == 32))
                    CSRHReadValM = HENVCFG_REGW[63:32];
                  else
                    IllegalCSRHAccessM = 1'b1;
      HTVAL:      if (LegalHAccessM) CSRHReadValM = HTVAL_REGW; else IllegalCSRHAccessM = 1'b1;
      HIP:        if (LegalHAccessM)
                    CSRHReadValM = {{(P.XLEN-12){1'b0}}, (HVIP_REGW | MIP_REGW)}; // Read-only derived value
                  else
                    IllegalCSRHAccessM = 1'b1;
      HVIP:       if (LegalHAccessM) CSRHReadValM = {{(P.XLEN-12){1'b0}}, HVIP_REGW}; else IllegalCSRHAccessM = 1'b1;
      HTINST:     if (LegalHAccessM) CSRHReadValM = HTINST_REGW; else IllegalCSRHAccessM = 1'b1;
      HGATP:      if (LegalHAccessM) CSRHReadValM = HGATP_REGW; else IllegalCSRHAccessM = 1'b1;
      HGEIP:      if (LegalHAccessM) CSRHReadValM = HGEIP_REGW; else IllegalCSRHAccessM = 1'b1;

      VSSTATUS:   if (LegalVSAccessM) CSRHReadValM = VSSTATUS_REGW; else IllegalCSRHAccessM = 1'b1;
      VSIE:       if (LegalVSAccessM) CSRHReadValM = {{(P.XLEN-12){1'b0}}, VSIE_REGW}; else IllegalCSRHAccessM = 1'b1;
      VSTVEC:     if (LegalVSAccessM) CSRHReadValM = VSTVEC_REGW; else IllegalCSRHAccessM = 1'b1;
      VSSCRATCH:  if (LegalVSAccessM) CSRHReadValM = VSSCRATCH_REGW; else IllegalCSRHAccessM = 1'b1;
      VSEPC:      if (LegalVSAccessM) CSRHReadValM = VSEPC_REGW; else IllegalCSRHAccessM = 1'b1;
      VSCAUSE:    if (LegalVSAccessM) CSRHReadValM = VSCAUSE_REGW; else IllegalCSRHAccessM = 1'b1;
      VSTVAL:     if (LegalVSAccessM) CSRHReadValM = VSTVAL_REGW; else IllegalCSRHAccessM = 1'b1;
      VSIP:       if (LegalVSAccessM) CSRHReadValM = {{(P.XLEN-12){1'b0}}, VSIP_REGW}; else IllegalCSRHAccessM = 1'b1;
      VSATP:      if (LegalVSAccessM & P.VIRTMEM_SUPPORTED) CSRHReadValM = VSATP_REGW; else IllegalCSRHAccessM = 1'b1;
      VSTIMECMP:  if (LegalVSAccessM & P.SSTC_SUPPORTED)
                    CSRHReadValM = VSTIMECMP_REGW[P.XLEN-1:0];
                  else
                    IllegalCSRHAccessM = 1'b1;
      VSTIMECMPH: if (LegalVSAccessM & P.SSTC_SUPPORTED & (P.XLEN == 32))
                    CSRHReadValM = VSTIMECMP_REGW[63:32];
                  else
                    IllegalCSRHAccessM = 1'b1;

      default:    IllegalCSRHAccessM = 1'b1;
    endcase

    if (CSRHWriteM && ReadOnlyCSR)
      IllegalCSRHAccessM = 1'b1;
  end

endmodule
