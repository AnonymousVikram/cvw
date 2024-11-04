
// Populate parameter structure with values specific to the current configuration

`include "BranchPredictorType.vh"

localparam cvw_t P = '{ 
  XLEN :                 XLEN,  
  IEEE754 :              IEEE754, 
  MISA :                 MISA, 
  AHBW :                 AHBW, 
  RAM_LATENCY :          RAM_LATENCY,
  BURST_EN :             BURST_EN,
  ZICSR_SUPPORTED :      ZICSR_SUPPORTED,
  ZIFENCEI_SUPPORTED :   ZIFENCEI_SUPPORTED,
  COUNTERS :             COUNTERS,
  ZICNTR_SUPPORTED :     ZICNTR_SUPPORTED,
  ZIHPM_SUPPORTED :      ZIHPM_SUPPORTED,
  ZFH_SUPPORTED :        ZFH_SUPPORTED,
  ZFA_SUPPORTED :        ZFA_SUPPORTED,
  SSTC_SUPPORTED :       SSTC_SUPPORTED,
  VIRTMEM_SUPPORTED :    VIRTMEM_SUPPORTED,
  VECTORED_INTERRUPTS_SUPPORTED : VECTORED_INTERRUPTS_SUPPORTED,
  BIGENDIAN_SUPPORTED :  BIGENDIAN_SUPPORTED,
  SVADU_SUPPORTED :      SVADU_SUPPORTED,
  ZMMUL_SUPPORTED :      ZMMUL_SUPPORTED,
  ZICBOM_SUPPORTED :     ZICBOM_SUPPORTED,
  ZICBOZ_SUPPORTED :     ZICBOZ_SUPPORTED,
  ZICBOP_SUPPORTED :     ZICBOP_SUPPORTED,
  ZICCLSM_SUPPORTED :    ZICCLSM_SUPPORTED,
  ZICOND_SUPPORTED :     ZICOND_SUPPORTED,
  SVPBMT_SUPPORTED :     SVPBMT_SUPPORTED,
  SVNAPOT_SUPPORTED :    SVNAPOT_SUPPORTED,
  SVINVAL_SUPPORTED :    SVINVAL_SUPPORTED,
  ZAAMO_SUPPORTED :      ZAAMO_SUPPORTED,
  ZALRSC_SUPPORTED :     ZALRSC_SUPPORTED, 
  BUS_SUPPORTED :        BUS_SUPPORTED,
  DCACHE_SUPPORTED :     DCACHE_SUPPORTED,
  ICACHE_SUPPORTED :     ICACHE_SUPPORTED,
  ITLB_ENTRIES :         ITLB_ENTRIES,
  DTLB_ENTRIES :         DTLB_ENTRIES,
  DCACHE_NUMWAYS :       DCACHE_NUMWAYS,
  DCACHE_WAYSIZEINBYTES :        DCACHE_WAYSIZEINBYTES,
  DCACHE_LINELENINBITS :        DCACHE_LINELENINBITS,
  ICACHE_NUMWAYS :        ICACHE_NUMWAYS,
  ICACHE_WAYSIZEINBYTES :        ICACHE_WAYSIZEINBYTES,
  ICACHE_LINELENINBITS :        ICACHE_LINELENINBITS,
  CACHE_SRAMLEN : CACHE_SRAMLEN,
  FETCHBUFFER_SUPPORTED : FETCHBUFFER_SUPPORTED,
  IDIV_BITSPERCYCLE :        IDIV_BITSPERCYCLE,
  IDIV_ON_FPU :        IDIV_ON_FPU,
  PMP_ENTRIES :        PMP_ENTRIES,
  RESET_VECTOR :        RESET_VECTOR,
  WFI_TIMEOUT_BIT :        WFI_TIMEOUT_BIT,
  DTIM_SUPPORTED :        DTIM_SUPPORTED,
  DTIM_BASE :        DTIM_BASE,
  DTIM_RANGE :        DTIM_RANGE,
  IROM_SUPPORTED :        IROM_SUPPORTED,
  IROM_BASE :        IROM_BASE,
  IROM_RANGE :        IROM_RANGE,
  BOOTROM_SUPPORTED :        BOOTROM_SUPPORTED,
  BOOTROM_BASE :        BOOTROM_BASE,
  BOOTROM_RANGE :        BOOTROM_RANGE,
  BOOTROM_PRELOAD : BOOTROM_PRELOAD,
  UNCORE_RAM_SUPPORTED :        UNCORE_RAM_SUPPORTED,
  UNCORE_RAM_BASE :        UNCORE_RAM_BASE,
  UNCORE_RAM_RANGE :        UNCORE_RAM_RANGE,
  UNCORE_RAM_PRELOAD : UNCORE_RAM_PRELOAD,
  EXT_MEM_SUPPORTED :        EXT_MEM_SUPPORTED,
  EXT_MEM_BASE :        EXT_MEM_BASE,
  EXT_MEM_RANGE :        EXT_MEM_RANGE,
  CLINT_SUPPORTED :        CLINT_SUPPORTED,
  CLINT_BASE :        CLINT_BASE,
  CLINT_RANGE :        CLINT_RANGE,
  GPIO_SUPPORTED :        GPIO_SUPPORTED,
  GPIO_BASE :        GPIO_BASE,
  GPIO_RANGE :        GPIO_RANGE,
  UART_SUPPORTED :        UART_SUPPORTED,
  UART_BASE :        UART_BASE,
  UART_RANGE :        UART_RANGE,
  PLIC_SUPPORTED :        PLIC_SUPPORTED,
  PLIC_BASE :        PLIC_BASE,
  PLIC_RANGE :        PLIC_RANGE,
  SDC_SUPPORTED :        SDC_SUPPORTED,
  SDC_BASE :        SDC_BASE,
  SDC_RANGE :        SDC_RANGE,
  SPI_SUPPORTED :        SPI_SUPPORTED,
  SPI_BASE :        SPI_BASE,
  SPI_RANGE :        SPI_RANGE,
  GPIO_LOOPBACK_TEST :        GPIO_LOOPBACK_TEST,
  SPI_LOOPBACK_TEST :        SPI_LOOPBACK_TEST,
  UART_PRESCALE :        UART_PRESCALE ,
  PLIC_NUM_SRC :        PLIC_NUM_SRC,
  PLIC_NUM_SRC_LT_32 :        PLIC_NUM_SRC_LT_32,
  PLIC_GPIO_ID :        PLIC_GPIO_ID,
  PLIC_UART_ID :        PLIC_UART_ID,
  PLIC_SPI_ID :        PLIC_SPI_ID,
  PLIC_SDC_ID :        PLIC_SDC_ID,
  BPRED_SUPPORTED :        BPRED_SUPPORTED,
                       /* verilator lint_off ENUMVALUE */
                       // *** definitely need to fix this.
                       // it thinks we are casting from the enum type to BPRED_TYPE.
  BPRED_TYPE :        BPRED_TYPE,
                       /* verilator lint_on ENUMVALUE */
  BPRED_SIZE :        BPRED_SIZE,
  BPRED_NUM_LHR : BPRED_NUM_LHR,                       
  BTB_SIZE :        BTB_SIZE,
  RAS_SIZE :        RAS_SIZE,
  INSTR_CLASS_PRED :  INSTR_CLASS_PRED,
  RADIX :        RADIX,
  DIVCOPIES :        DIVCOPIES,
  ZBA_SUPPORTED :        ZBA_SUPPORTED,
  ZBB_SUPPORTED :        ZBB_SUPPORTED,
  ZBC_SUPPORTED :        ZBC_SUPPORTED,
  ZBS_SUPPORTED :        ZBS_SUPPORTED,
  ZCA_SUPPORTED :        ZCA_SUPPORTED,
  ZCB_SUPPORTED :        ZCB_SUPPORTED,
  ZCD_SUPPORTED :        ZCD_SUPPORTED,
  ZCF_SUPPORTED :        ZCF_SUPPORTED,
  ZBKB_SUPPORTED:        ZBKB_SUPPORTED,
  ZBKC_SUPPORTED:        ZBKC_SUPPORTED,
  ZBKX_SUPPORTED:        ZBKX_SUPPORTED,
  ZKND_SUPPORTED:        ZKND_SUPPORTED,
  ZKNE_SUPPORTED:        ZKNE_SUPPORTED,
  ZKNH_SUPPORTED:        ZKNH_SUPPORTED,
  ZKN_SUPPORTED :        ZKN_SUPPORTED,
  USE_SRAM :        USE_SRAM,
  M_MODE  : M_MODE, 
  S_MODE  : S_MODE, 
  U_MODE  : U_MODE, 
  VPN_SEGMENT_BITS : VPN_SEGMENT_BITS,
  VPN_BITS : VPN_BITS,
  PPN_BITS : PPN_BITS,
  PA_BITS : PA_BITS,
  SVMODE_BITS : SVMODE_BITS,
  ASID_BASE : ASID_BASE,
  ASID_BITS : ASID_BITS,
  NO_TRANSLATE : NO_TRANSLATE,
  SV32 : SV32,
  SV39 : SV39,
  SV48 : SV48,
  A_SUPPORTED : A_SUPPORTED,
  B_SUPPORTED : B_SUPPORTED,
  C_SUPPORTED : C_SUPPORTED,
  D_SUPPORTED : D_SUPPORTED,
  E_SUPPORTED : E_SUPPORTED,
  F_SUPPORTED : F_SUPPORTED,
  I_SUPPORTED : I_SUPPORTED,
  M_SUPPORTED : M_SUPPORTED,
  Q_SUPPORTED : Q_SUPPORTED,
  S_SUPPORTED : S_SUPPORTED,
  U_SUPPORTED : U_SUPPORTED,
  LOG_XLEN : LOG_XLEN,
  PMPCFG_ENTRIES : PMPCFG_ENTRIES,
  Q_LEN : Q_LEN,
  Q_NE : Q_NE,
  Q_NF : Q_NF,
  Q_BIAS : Q_BIAS,
  Q_FMT : Q_FMT,
  D_LEN : D_LEN,
  D_NE : D_NE,
  D_NF : D_NF,
  D_BIAS : D_BIAS,
  D_FMT : D_FMT,
  S_LEN : S_LEN,
  S_NE : S_NE,
  S_NF : S_NF,
  S_BIAS : S_BIAS,
  S_FMT : S_FMT,
  H_LEN : H_LEN,
  H_NE : H_NE,
  H_NF : H_NF,
  H_BIAS : H_BIAS,
  H_FMT : H_FMT,
  FLEN : FLEN,
  LOGFLEN : LOGFLEN,
  NE   : NE  ,
  NF   : NF  ,
  FMT  : FMT ,
  BIAS : BIAS,
  FPSIZES : FPSIZES,
  FMTBITS : FMTBITS,
  LEN1  : LEN1 ,
  NE1   : NE1  ,
  NF1   : NF1  ,
  FMT1  : FMT1 ,
  BIAS1 : BIAS1,
  LEN2  : LEN2 ,
  NE2   : NE2  ,
  NF2   : NF2  ,
  FMT2  : FMT2 ,
  BIAS2 : BIAS2,
  CVTLEN : CVTLEN,
  LLEN : LLEN,
  LOGCVTLEN : LOGCVTLEN,
  FMALEN : FMALEN,
  NORMSHIFTSZ : NORMSHIFTSZ,
  LOGNORMSHIFTSZ : LOGNORMSHIFTSZ,
  LOGR        : LOGR,
  RK          : RK,
  FPDUR       : FPDUR,
  DURLEN      : DURLEN,
  DIVb        : DIVb,
  DIVBLEN     : DIVBLEN,
  INTDIVb     : INTDIVb
};

