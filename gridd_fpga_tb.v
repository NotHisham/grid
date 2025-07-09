`timescale 1ns/1ps
module tb_gridd_fpga;
    reg clk = 0, reset = 1;
    wire [3:0] leds;

    EV_USP_CS_FPGA dut (.clk(clk), .reset(reset), .leds(leds));

    always #5 clk = ~clk;

    initial begin
        $dumpfile("wave.vcd");
        $dumpvars(0, tb_gridd_fpga);
        #10 reset = 0;
        #200 $finish;
    end
endmodule
