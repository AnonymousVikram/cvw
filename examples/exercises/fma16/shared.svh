/**********************************************************************
  * File: fma16_shared.svh
  * Description: Shared definitions for the FMA16 project
  * Author: Vikram Krishna (vkrishna@hmc.edu)
  * Created: April 19, 2025
  * Last Modified: April 21, 2025
**********************************************************************/

`ifndef FMA16_SHARED_SVH
`define FMA16_SHARED_SVH

package fma16_shared;

typedef struct packed {
    logic nan;
    logic snan;
    logic inf;
    logic zero;
    logic subnorm;
    logic sign;
    logic [4:0] exp;
    logic [10:0] sig;
  } float16_t;

endpackage;

`endif
