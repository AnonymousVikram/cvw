# fma.do 
#
# run with vsim -do "do fma.do"
# add -c before -do for batch simulation

onbreak {resume}

# create library
vlib worklib

vlog -lint -sv -work worklib fma16.sv testbench.sv multiplier.sv adder.sv shifter.sv postproc.sv unpack.sv
vopt +acc worklib.testbench_fma16 -work worklib -o testbenchopt
vsim -lib worklib testbenchopt

add wave sim:/testbench_fma16/clk
add wave sim:/testbench_fma16/reset
add wave sim:/testbench_fma16/x
add wave sim:/testbench_fma16/y
add wave sim:/testbench_fma16/z
add wave sim:/testbench_fma16/result
add wave sim:/testbench_fma16/rexpected
add wave -noupdate /testbench_fma16/clk
add wave -noupdate /testbench_fma16/reset
add wave -noupdate /testbench_fma16/x
add wave -noupdate /testbench_fma16/y
add wave -noupdate /testbench_fma16/z
add wave -noupdate /testbench_fma16/result
add wave -noupdate /testbench_fma16/rexpected
add wave -noupdate -divider fma16
add wave -noupdate /testbench_fma16/dut/xParsed
add wave -noupdate /testbench_fma16/dut/yParsed
add wave -noupdate /testbench_fma16/dut/zParsed
add wave -noupdate /testbench_fma16/dut/result

run -all
