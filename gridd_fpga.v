`timescale 1ns/1ps
// ============================================================================
//  EV–USP–CS Secure Authentication System with Simulation Support
//  * Target: Xilinx Zynq UltraScale+ ZC104
//  * LFSR-based nonce and timestamp (synthesizable)
//  * LEDs: {final_ack, auth_pass, reg_ack_cs, reg_ack_ev}
//  * Distinct Phases: [EV→USP Registration] → [CS→USP Registration] → [EV→CS Authentication]
//  * Includes: Single Top + Three Simulation Testbenches
// ============================================================================

// ===================== PHASE 1: EV → USP Registration =====================
module HashFunction(input [63:0] data_in, output reg [63:0] hash_out);
    reg [63:0] state;
    always @(*) begin
        state = data_in ^ 64'hA5A5_A5A5_A5A5_A5A5;
        state = {state[31:0], state[63:32]} ^ 64'hC3D2_E1F0_DEAD_BEEF;
        state = ~state ^ (state >> 1);
        hash_out = state;
    end
endmodule

module PUF(input [15:0] challenge, output reg response);
    wire [15:0] mix = challenge ^ {challenge[7:0], challenge[15:8]};
    always @(*) response = ^mix;
endmodule

module Encryptor(input [63:0] data_in, output [63:0] data_out);
    assign data_out = data_in ^ 64'hDEAD_BEEF_CAFE_BABE;
endmodule

module Decryptor(input [63:0] data_in, output [63:0] data_out);
    assign data_out = data_in ^ 64'hDEAD_BEEF_CAFE_BABE;
endmodule

module EV(
    input clk, input reset,
    output reg [15:0] ev_id,
    output reg [15:0] ev_nonce,
    output reg [31:0] ev_time,
    output reg [63:0] encrypted_msg,
    output reg puf_resp,
    output reg send_reg,
    output reg send_req
);
    localparam [15:0] EV_ID_DEFAULT = 16'h00EF;

    reg [2:0] state;
    localparam IDLE=0, REG=1, PREP=2, SEND=3, WAIT=4, DONE=5;

    reg [15:0] nonce_reg;
    wire lfsr_feedback = nonce_reg[15] ^ nonce_reg[13] ^ nonce_reg[12] ^ nonce_reg[10];
    always @(posedge clk or posedge reset)
        if (reset) nonce_reg <= 16'hACE1;
        else       nonce_reg <= {nonce_reg[14:0], lfsr_feedback};

    reg [31:0] ts_lfsr;
    wire ts_feedback = ts_lfsr[31] ^ ts_lfsr[21] ^ ts_lfsr[1] ^ ts_lfsr[0];
    always @(posedge clk or posedge reset)
        if (reset) ts_lfsr <= 32'h1A2B3C4D;
        else       ts_lfsr <= {ts_lfsr[30:0], ts_feedback};

    wire [63:0] hash_out, enc_out;
    wire puf_out;

    HashFunction hf (.data_in({ev_id, nonce_reg, ts_lfsr}), .hash_out(hash_out));
    Encryptor enc (.data_in(hash_out), .data_out(enc_out));
    PUF p (.challenge(ev_id ^ nonce_reg), .response(puf_out));

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            state <= IDLE;
            ev_id <= EV_ID_DEFAULT;
            ev_time <= 0;
            ev_nonce <= 0;
            encrypted_msg <= 0;
            puf_resp <= 0;
            send_reg <= 0;
            send_req <= 0;
        end else begin
            case (state)
                IDLE: begin ev_time <= ts_lfsr; state <= REG; end
                REG:  begin send_reg <= 1; state <= PREP; end
                PREP: begin
                    send_reg <= 0;
                    ev_nonce <= nonce_reg;
                    encrypted_msg <= enc_out;
                    puf_resp <= puf_out;
                    send_req <= 1;
                    state <= SEND;
                end
                SEND: begin send_req <= 0; state <= WAIT; end
                WAIT: state <= DONE;
                DONE: ; // Hold
            endcase
        end
    end
endmodule

// ===================== PHASE 2: CS → USP Registration =====================
// Contains CS module and its registration with USP.
module USP(
    input clk, input reset,
    input [15:0] ev_id, input [15:0] cs_id,
    input send_reg_ev, input send_reg_cs,
    input [63:0] encrypted_msg, input puf_resp, input send_req,
    output reg [63:0] usp_tag, output reg auth_pass,
    output reg reg_ack_ev, output reg reg_ack_cs, output reg send_to_cs
);
    reg [15:0] reg_db_ev, reg_db_cs;
    reg [2:0] state;
    localparam IDLE = 0, REG_EV = 1, REG_CS = 2, VERIFY = 3, RESPOND = 4;
    wire [63:0] decrypted_msg;

    Decryptor dec (.data_in(encrypted_msg), .data_out(decrypted_msg));

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            auth_pass <= 0; reg_ack_ev <= 0; reg_ack_cs <= 0;
            reg_db_ev <= 0; reg_db_cs <= 0;
            send_to_cs <= 0; usp_tag <= 0; state <= IDLE;
        end else begin
            case (state)
                IDLE:
                    if (send_reg_ev) state <= REG_EV;
                    else if (send_reg_cs) state <= REG_CS;
                    else if (send_req) state <= VERIFY;
                REG_EV: begin reg_db_ev <= ev_id; reg_ack_ev <= 1; state <= IDLE; end
                REG_CS: begin reg_db_cs <= cs_id; reg_ack_cs <= 1; state <= IDLE; end
                VERIFY: begin
                    reg_ack_ev <= 0; reg_ack_cs <= 0;
                    if (reg_db_ev == ev_id && decrypted_msg[7:0] == 8'h5A && puf_resp) begin
                        auth_pass <= 1;
                        usp_tag <= decrypted_msg ^ 64'hCAFEBABEDEADBEEF;
                        send_to_cs <= 1;
                    end else begin
                        auth_pass <= 0; send_to_cs <= 0;
                    end
                    state <= RESPOND;
                end
                RESPOND: send_to_cs <= 0;
            endcase
        end
    end
endmodule

// ===================== PHASE 3: EV → CS Authentication =====================
// Contains full authentication flow from EV to CS via USP

module CS(
    input clk, input reset,
    input [15:0] cs_id, input send_reg_cs,
    input send_to_cs, input [63:0] usp_tag, input auth_pass,
    output reg final_ack, output reg reg_ack_cs
);
    reg [15:0] reg_db_cs;
    wire [7:0] tag_check_byte = (usp_tag ^ 64'hCAFEBABEDEADBEEF) & 8'hFF;

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            final_ack <= 0; reg_ack_cs <= 0; reg_db_cs <= 0;
        end else begin
            if (send_reg_cs) begin
                reg_db_cs <= cs_id; reg_ack_cs <= 1;
            end else if (send_to_cs && reg_db_cs == cs_id) begin
                if (tag_check_byte == 8'h5A && auth_pass)
                    final_ack <= 1;
                else
                    final_ack <= 0;
            end
        end
    end
endmodule

module EV_USP_CS_FPGA(
    input clk, input reset,
    output [3:0] leds
);
    wire [15:0] ev_id, ev_nonce, cs_id = 16'h0C51;
    wire [31:0] ev_time;
    wire [63:0] encrypted_msg, usp_tag;
    wire puf_resp, send_req, auth_pass, final_ack, send_reg_ev, reg_ack_ev;
    wire reg_ack_cs_usp, reg_ack_cs_cs, send_to_cs;
    wire send_reg_cs = 1'b1;

    EV ev (
        .clk(clk), .reset(reset),
        .ev_id(ev_id), .ev_nonce(ev_nonce), .ev_time(ev_time),
        .encrypted_msg(encrypted_msg), .puf_resp(puf_resp),
        .send_req(send_req), .send_reg(send_reg_ev)
    );

    USP usp (
        .clk(clk), .reset(reset),
        .ev_id(ev_id), .cs_id(cs_id),
        .send_reg_ev(send_reg_ev), .send_reg_cs(send_reg_cs),
        .encrypted_msg(encrypted_msg), .puf_resp(puf_resp), .send_req(send_req),
        .auth_pass(auth_pass), .reg_ack_ev(reg_ack_ev), .reg_ack_cs(reg_ack_cs_usp),
        .usp_tag(usp_tag), .send_to_cs(send_to_cs)
    );

    CS cs (
        .clk(clk), .reset(reset), .cs_id(cs_id), .send_reg_cs(send_reg_cs),
        .send_to_cs(send_to_cs), .usp_tag(usp_tag), .auth_pass(auth_pass),
        .final_ack(final_ack), .reg_ack_cs(reg_ack_cs_cs)
    );

    assign leds = {final_ack, auth_pass, reg_ack_cs_usp, reg_ack_ev};
endmodule
// Contains CS module and its registration with USP.

// ===================== PHASE 3: EV → CS Authentication =====================
// Contains full authentication flow from EV to CS via USP.

// NOTE: Testbenches have been moved to a separate simulation source file.


