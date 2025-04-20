typedef struct packed {
    logic sign;
    logic [4:0] exp;
    logic [9:0] sig;
  } float16_t;
