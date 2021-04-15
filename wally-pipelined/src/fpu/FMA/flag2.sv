/////////////////////////////////////////////////////////////////////////////// 
// Block Name:	flag.v
// Author:		David Harris
// Date:		12/6/1995
//
// Block Description:
//       This block generates the flags: invalid, overflow, underflow, inexact. 
/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
module flag2(xsign,ysign,zsign, xnanM, ynanM, znanM, xinfM, yinfM, zinfM, sumof, sumuf,
			 xzeroM, yzeroM, zzeroM, vbits, killprodM,
			 inf, nanM, FmaFlagsM,sticky,prodinfM);
/////////////////////////////////////////////////////////////////////////////

	input                  		xnanM;        	// X is NaN 
	input                  		ynanM;        	// Y is NaN 
	input                 		znanM;       	// Z is NaN 
	input				xsign; 		// Sign of z
	input				ysign; 		// Sign of z
	input				zsign; 		// Sign of z
	input                  		sticky;        	// X is Inf
    input                       prodinfM;
	input                  		xinfM;        	// X is Inf
	input                 		yinfM;       	// Y is Inf 
	input                  		zinfM;        	// Z is Inf
	input                  		sumof;          // X*Y + z underflows exponent
	input                  		sumuf;          // X*Y + z underflows exponent
	input				xzeroM;		// x = 0
	input				yzeroM;		// y = 0
	input				zzeroM;		// y = 0
	input				killprodM;
	input     	[1:0]  		vbits;		// R and S bits of result
	output				inf;		// Some	source is Inf
	output				nanM;		// Some	source is NaN
	output		[4:0]	FmaFlagsM;
 
	//   Internal nodes

logic suminf;

	// Same with infinity (inf - inf and O * inf don't propagate inf
	//  but it's ok becaue illegal op takes higher precidence)

	assign inf= xinfM || yinfM || zinfM || suminf;//KEP added suminf 
	//assign inf= xinfM || yinfM || zinfM;//original

	assign suminf = sumof && ~xnanM && ~ynanM && ~znanM;


	// Set the overflow flag for the following cases:
	//   1) Rounded multiply result would be out of bounds
	//   2) Rounded add result would be out of bounds

	assign FmaFlagsM[2] = suminf && ~inf;

	// Set the underflow  flag for the following cases:
	//   1) Any input is denormalized
	//   2)  Output would be denormalized or smaller

	assign FmaFlagsM[1] = (sumuf && ~inf && ~prodinfM && ~nanM) || (killprodM & zzeroM & ~(yzeroM | xzeroM));

	// Set the inexact flag for the following cases:
	//   1) Multiplication inexact
	//   2) Addition  inexact
	// One of these cases occurred if the R or S bit is set

	assign FmaFlagsM[0] = (vbits[0] || vbits[1] ||sticky  || suminf) && ~(inf || nanM);

	// Set invalid flag for following cases:
	//   1) Inf - Inf
	//   2) 0 * Inf
	//   3) Output = NaN (this is not part of the IEEE spec,  only 486 proj)

	assign FmaFlagsM[4] = (xinfM || yinfM || prodinfM) && zinfM && (xsign ^ ysign ^ zsign) ||
					   xzeroM && yinfM || yzeroM && xinfM;// KEP remove case 3) above

	assign FmaFlagsM[3] = 0; // divide by zero flag

endmodule
