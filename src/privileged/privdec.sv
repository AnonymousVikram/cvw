///////////////////////////////////////////
// privdec.sv
//
// Written: David_Harris@hmc.edu 9 January 2021
// Modified:
//
// Purpose: Decode Privileged & related instructions
//          See RISC-V Privileged Mode Specification 20190608 3.1.10-11
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

module privdec import cvw::*;  #(parameter cvw_t P) (
  input  logic         clk, reset,
  input  logic         StallW, FlushW,
  input  logic [31:7 ] InstrM,                              // privileged instruction function field
  input  logic         PrivilegedM,                         // is this a privileged instruction (from IEU controller)
  input  logic         IllegalIEUFPUInstrM,                 // Not a legal IEU instruction
  input  logic         IllegalCSRAccessM,                   // Not a legal CSR access
  input  logic [1:0]   PrivilegeModeW,                      // current privilege level
  input  logic         VirtModeW,                           // virtualization bit
  input  logic         [P.XLEN - 1:0] HSTATUS_REGW,         // hstatus register
  input  logic         STATUS_TSR, STATUS_TVM, STATUS_TW,   // status bits
  output logic         IllegalInstrFaultM,                  // Illegal instruction
  output logic         VirtualInstrFaultM,                  // Virtual instruction exception
  output logic         EcallFaultM, BreakpointFaultM,       // Ecall or breakpoint; must retire, so don't flush it when the trap occurs
  output logic         sretM, mretM, RetM,                  // return instructions
  output logic         wfiM, wfiW, sfencevmaM,              // wfi / sfence.vma / sinval.vma instructions
  output logic         hfencevvmaM, hfencegvmaM             // Hypervisor fence instructions
);

  logic                rs1zeroM, rdzeroM;                   // rs1 / rd field = 0
  logic                IllegalPrivilegedInstrM;             // privileged instruction isn't a legal one or in legal mode
  logic                WFITimeoutM;                         // WFI reaches timeout threshold
  logic                ebreakM, ecallM;                     // ebreak / ecall instructions
  logic                sinvalvmaM;                          // sinval.vma
  logic                presfencevmaM;                       // sfence.vma before checking privilege mode
  logic                sfencewinvalM, sfenceinvalirM;       // sfence.w.inval, sfence.inval.ir
  logic                vmaM;                                // sfence.vma or sinval.vma
  logic                fenceinvalM;                         // sfence.w.inval or sfence.inval.ir

  // hypervisor decoding
  logic                prehfencevvmaM, prehfencegvmaM;      // hfence.vvma, hfence.gvma
  logic                hinvalvvmaM, hinvalgvmaM;            // hinval.vvma, hinval.gvma
  logic                hvmaM;                               // fence signal (hfence.vvma or hfence.gvma or hinval.vvma or hinval.gvma)
  logic                WFITimeoutVirtualM;                  // WFI reaches timeout threshold for hypervisor
  logic                HSTATUS_VTW;                          // hstatus.vtw [21]

  ///////////////////////////////////////////
  // Decode privileged instructions
  ///////////////////////////////////////////

  assign rs1zeroM =    InstrM[19:15] == 5'b0;
  assign rdzeroM  =    InstrM[11:7]  == 5'b0;

  // svinval instructions
  // any svinval instruction is treated as sfence.vma on Wally
  assign sinvalvmaM     = (InstrM[31:25] ==  7'b0001011)                 & rdzeroM;
  assign sfencewinvalM  = (InstrM[31:20] == 12'b000110000000) & rs1zeroM & rdzeroM;
  assign sfenceinvalirM = (InstrM[31:20] == 12'b000110000001) & rs1zeroM & rdzeroM;
  assign presfencevmaM  = (InstrM[31:25] ==  7'b0001001)                 & rdzeroM;
  assign vmaM           =  presfencevmaM | (sinvalvmaM & P.SVINVAL_SUPPORTED);      // sfence.vma or sinval.vma
  assign fenceinvalM    = (sfencewinvalM | sfenceinvalirM) & P.SVINVAL_SUPPORTED;   // sfence.w.inval or sfence.inval.ir

  assign sretM =      PrivilegedM & (InstrM[31:20] == 12'b000100000010) & rs1zeroM & P.S_SUPPORTED &
                      (PrivilegeModeW == P.M_MODE | PrivilegeModeW == P.S_MODE & ~STATUS_TSR);
  assign mretM =      PrivilegedM & (InstrM[31:20] == 12'b001100000010) & rs1zeroM & (PrivilegeModeW == P.M_MODE);
  assign RetM =       sretM | mretM;
  assign ecallM =     PrivilegedM & (InstrM[31:20] == 12'b000000000000) & rs1zeroM;
  assign ebreakM =    PrivilegedM & (InstrM[31:20] == 12'b000000000001) & rs1zeroM;
  assign wfiM =       PrivilegedM & (InstrM[31:20] == 12'b000100000101) & rs1zeroM;

  // all of sinval.vma, sfence.w.inval, sfence.inval.ir are treated as sfence.vma
  assign sfencevmaM = PrivilegedM & P.VIRTMEM_SUPPORTED &
                      ((PrivilegeModeW == P.M_MODE & (vmaM | fenceinvalM)) |
                       (PrivilegeModeW == P.S_MODE & (vmaM & ~STATUS_TVM  | fenceinvalM))); // sfence.w.inval & sfence.inval.ir not affected by TVM

  // Decode hypervisor privileged instructions
  assign prehfencevvmaM = (InstrM[31:25] == 7'b0010001) & rdzeroM;
  assign prehfencegvmaM = (InstrM[31:25] == 7'b0110001) & rdzeroM;
  assign hinvalvvmaM = (InstrM[31:25] == 7'b0010011) & rdzeroM;
  assign hinvalgvmaM = (InstrM[31:25] == 7'b0110011) & rdzeroM;

  assign hvmaM = prehfencevvmaM | prehfencegvmaM | ((hinvalvvmaM | hinvalgvmaM) & P.SVINVAL_SUPPORTED); // hfence.vvma or hfence.gvma or hinval.vvma or hinval.gvma

  // Hypervisor fences are only legal in M mode or HS mode when TVM = 0 (S Mode is not supported)
  // hfence.vvma and hfence.gvma raises an illegal instruction exception when TVM = 1 in HS mode
  assign hfencevvmaM = PrivilegedM & P.VIRTMEM_SUPPORTED & P.H_SUPPORTED &
                       (prehfencevvmaM | (hinvalvvmaM & P.SVINVAL_SUPPORTED)) &
                       ((PrivilegeModeW == P.M_MODE) | (PrivilegeModeW == P.S_MODE & ~VirtModeW & ~STATUS_TVM));
  assign hfencegvmaM = PrivilegedM & P.VIRTMEM_SUPPORTED & P.H_SUPPORTED &
                       (prehfencegvmaM | (hinvalgvmaM & P.SVINVAL_SUPPORTED)) &
                       ((PrivilegeModeW == P.M_MODE) | (PrivilegeModeW == P.S_MODE & ~VirtModeW & ~STATUS_TVM));

  ///////////////////////////////////////////
  // WFI timeout Privileged Spec 3.1.6.5
  ///////////////////////////////////////////

  // Supports privileged and hypervisor
  if (P.U_SUPPORTED) begin:wfi
    logic [P.WFI_TIMEOUT_BIT:0] WFICount, WFICountPlus1;
    assign WFICountPlus1 = wfiM ? WFICount + 1 : '0; // restart counting on WFI
    flopr #(P.WFI_TIMEOUT_BIT+1) wficountreg(clk, reset, WFICountPlus1, WFICount);  // count while in WFI
  // coverage off -item e 1 -fecexprrow 1
  // WFI Timeout trap will not occur when STATUS_TW is low while in supervisor mode, so the system gets stuck waiting for an interrupt and triggers a watchdog timeout.
    assign WFITimeoutM = ((STATUS_TW & PrivilegeModeW != P.M_MODE) | (P.S_SUPPORTED & PrivilegeModeW == P.U_MODE)) & WFICount[P.WFI_TIMEOUT_BIT];
  // Raises virtual instruction exception in VS mode, VTW = 1, and mstatus.TW = 0
    assign HSTATUS_VTW = HSTATUS_REGW[21];
    assign WFITimeoutVirtualM = P.H_SUPPORTED & VirtModeW &
                                (PrivilegeModeW == P.S_MODE) &
                                HSTATUS_VTW & ~STATUS_TW &
                                WFICount[P.WFI_TIMEOUT_BIT];
  // coverage on
  end else begin
    assign WFITimeoutM = 1'b0;
    assign WFITimeoutVirtualM = 1'b0;
  end

  flopenrc #(1) wfiWReg(clk, reset, FlushW, ~StallW, wfiM, wfiW);

  ///////////////////////////////////////////
  // Virtual Instruction Exceptions
  ///////////////////////////////////////////

  if (P.H_SUPPORTED) begin: virt_instr
    logic VirtSFenceVMAFaultM;
    logic VirtHFenceFaultM;
    logic VirtSRETFaultM;
    logic VirtWFIFaultM;
    logic HSTATUS_VTVM, HSTATUS_VTSR;

    assign HSTATUS_VTVM = HSTATUS_REGW[20]; // VTVM bit
    assign HSTATUS_VTSR = HSTATUS_REGW[22]; // VTSR bit

    // sfence.vma or sinval.vma in VS mode causes exception when VTVM = 1 or VU mode
    assign VirtSFenceVMAFaultM = VirtModeW & PrivilegedM & (vmaM | fenceinvalM) &
                                 P.VIRTMEM_SUPPORTED & ((PrivilegeModeW == P.S_MODE & HSTATUS_VTVM) | (PrivilegeModeW == P.U_MODE));

    // hfence.vvma/gvma or hinval.vvma/gvma always causes virtual instruction exception in VS/VU mode
    assign VirtHFenceFaultM = VirtModeW & PrivilegedM & hvmaM & P.VIRTMEM_SUPPORTED;

    // sret in VS mode with VTSR = 1, or VU mode
    assign VirtSRETFaultM = VirtModeW & PrivilegedM & sretM &
                            ((PrivilegeModeW == P.S_MODE & HSTATUS_VTSR) | (PrivilegeModeW == P.U_MODE));
    // WFI causes exception in VU mode when TW = 0 or in VS mode when VTW = 1 and TW = 0
    assign VirtWFIFaultM = VirtModeW & wfiM & ~STATUS_TW &
                           ((PrivilegeModeW == P.S_MODE & HSTATUS_VTW) | (PrivilegeModeW == P.U_MODE));

    assign VirtualInstrFaultM = VirtSFenceVMAFaultM | VirtHFenceFaultM | VirtSRETFaultM | VirtWFIFaultM;


  end

  else begin : no_virt_instr
    assign VirtualInstrFaultM = 1'b0;

  end

  ///////////////////////////////////////////
  // Extract exceptions by name and handle them
  ///////////////////////////////////////////

  assign BreakpointFaultM = ebreakM; // could have other causes from a debugger
  assign EcallFaultM = ecallM;

  ///////////////////////////////////////////
  // Fault on illegal instructions
  ///////////////////////////////////////////

  assign IllegalPrivilegedInstrM = PrivilegedM & ~(sretM|mretM|ecallM|ebreakM|wfiM|sfencevmaM|hfencevvmaM|hfencegvmaM);
  assign IllegalInstrFaultM = IllegalIEUFPUInstrM | IllegalPrivilegedInstrM | IllegalCSRAccessM |
                              WFITimeoutM;
endmodule
