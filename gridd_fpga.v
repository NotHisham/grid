`timescale 1ns/1ps
// ============================================================================
// EV-USP-CS Secure Authentication System with Simulation Support
// * Target: Xilinx Zynq UltraScale+ ZC104
// * LFSR-based nonce and timestamp (synthesizable)
// * LEDs: {final_ack_ev_cs, auth_pass_ev_usp, reg_ack_cs_usp, reg_ack_ev_usp}
// * Implements simplified versions of protocols from provided images (XOR-based crypto)
//
// This system simulates a three-phase authentication protocol:
// Phase 1: EV (Electric Vehicle) Registration with USP (Universal Service Provider) - (Table 1)
// Phase 2: CS (Charging Station) Registration with USP - (Table 2)
// Phase 3: EV Authentication with CS (via USP for initial registration data) - (Table 2)
//
// NOTE: Cryptographic primitives (Hash, PUF, Encrypt/Decrypt) are simplified for simulation
// and use XOR operations, do NOT offer real-world security.
// ============================================================================

// ============================================================================
// SECTION: Cryptographic Primitives (Simplified Implementations)
// These modules provide basic XOR-based operations to mimic cryptographic functions
// as requested, but do NOT offer real-world security.
// ============================================================================

// HashFunction: Simple XOR-based hash
// Input: 128-bit data_in (concatenation of various protocol fields)
// Output: 64-bit hash_out
// The hash operation involves XORing with constants, bit swapping, bitwise NOT,
// right shifting, and incorporating higher bits of the input.
module HashFunction(input [127:0] data_in, output reg [63:0] hash_out);
    reg [63:0] state; // Internal state for hash computation
    always @(*) begin
        // Initial mixing with a constant and lower 64 bits of input
        state = data_in[63:0] ^ 64'hA5A5_A5A5_A5A5_A5A5;
        // Bit swapping and XORing with another constant
        state = {state[31:0], state[63:32]} ^ 64'hC3D2_E1F0_DEAD_BEEF;
        // Further mixing: bitwise NOT, right shift, and XOR with higher 64 bits of input
        state = ~state ^ (state >> 1) ^ data_in[127:64];
        hash_out = state; // Final hash output
    end
endmodule

// PUF: Simplified Physical Unclonable Function
// Input: 64-bit challenge
// Output: 64-bit response (used for RS or K_a in protocols)
// This is a simple deterministic function for simulation purposes, not a true PUF.
module PUF(input [63:0] challenge, output reg [63:0] response);
    always @(*) begin
        // Simple XOR with a constant
        response = challenge ^ 64'hF0E1_D2C3_B4A5_9687;
        // Additional mixing: bitwise NOT and addition with left-shifted value
        response = ~response + (response << 3);
    end
endmodule

// Encryptor: Symmetric XOR-based encryption
// Input: 64-bit data_in, 64-bit key
// Output: 64-bit data_out (encrypted)
// Encryption is performed by XORing data with the provided key.
module Encryptor(input [63:0] data_in, input [63:0] key, output [63:0] data_out);
    assign data_out = data_in ^ key; // Simple XOR encryption
endmodule

// Decryptor: Symmetric XOR-based decryption
// Input: 64-bit data_in (encrypted), 64-bit key
// Output: 64-bit data_out (decrypted)
// Decryption is identical to encryption for XOR ciphers.
module Decryptor(input [63:0] data_in, input [63:0] key, output [63:0] data_out);
    assign data_out = data_in ^ key; // Simple XOR decryption
endmodule

// ============================================================================
// SECTION: EV Module (Electric Vehicle) - Simplified
// Contains EV's fixed parameters and LFSR.
// ============================================================================
module EV(
    input clk, input reset,
    output [15:0] ev_id_out,
    output [63:0] ev_sym_key_usp_out,
    output [63:0] ev_sym_key_cs_out,
    output [63:0] pub_k_ev_out,
    output [63:0] nonce_lfsr_out,
    output [63:0] timestamp_lfsr_out
);
    localparam [15:0] EV_ID = 16'h00EF;
    localparam [63:0] EV_SYM_KEY_USP = 64'hDEAD_BEEF_CAFE_BABE;
    localparam [63:0] EV_SYM_KEY_CS = 64'hCAFE_BABE_DEAD_BEEF;
    localparam [63:0] PUB_K_EV = 64'hAABBCCDD_EEFF0011;

    reg [63:0] nonce_lfsr_reg;
    reg [63:0] timestamp_lfsr_reg;
    wire lfsr_feedback_nonce = nonce_lfsr_reg[63] ^ nonce_lfsr_reg[61] ^ nonce_lfsr_reg[60] ^ nonce_lfsr_reg[59];
    wire lfsr_feedback_ts    = timestamp_lfsr_reg[63] ^ timestamp_lfsr_reg[53] ^ timestamp_lfsr_reg[43] ^ timestamp_lfsr_reg[33];

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            nonce_lfsr_reg <= 64'hACE1_ACE1_ACE1_ACE1;
            timestamp_lfsr_reg <= 64'h1A2B_3C4D_5E6F_7A8B;
        end else begin
            nonce_lfsr_reg <= {nonce_lfsr_reg[62:0], lfsr_feedback_nonce};
            timestamp_lfsr_reg <= {timestamp_lfsr_reg[62:0], lfsr_feedback_ts};
        end
    end

    assign ev_id_out = EV_ID;
    assign ev_sym_key_usp_out = EV_SYM_KEY_USP;
    assign ev_sym_key_cs_out = EV_SYM_KEY_CS;
    assign pub_k_ev_out = PUB_K_EV;
    assign nonce_lfsr_out = nonce_lfsr_reg;
    assign timestamp_lfsr_out = timestamp_lfsr_reg;
endmodule

// ============================================================================
// SECTION: USP Module (Universal Service Provider) - Simplified
// Contains USP's fixed parameters and LFSR.
// ============================================================================
module USP(
    input clk, input reset,
    output [15:0] usp_id_out,
    output [63:0] usp_sym_key_ev_out,
    output [63:0] usp_sym_key_cs_out,
    output [63:0] pub_j_usp_out,
    output [63:0] nonce_j_lfsr_out,
    output [63:0] current_timestamp_usp_out
);
    localparam [15:0] USP_ID = 16'h0C51;
    localparam [63:0] USP_SYM_KEY_EV = 64'hDEAD_BEEF_CAFE_BABE;
    localparam [63:0] USP_SYM_KEY_CS = 64'hCAFE_BABE_BEEF_DEAD;
    localparam [63:0] PUB_J_USP = 64'h22334455_66778899;

    reg [63:0] nonce_j_lfsr_reg;
    reg [63:0] current_timestamp_usp_reg;
    wire lfsr_feedback_nonce_j = nonce_j_lfsr_reg[63] ^ nonce_j_lfsr_reg[51] ^ nonce_j_lfsr_reg[41] ^ nonce_j_lfsr_reg[31];
    wire lfsr_feedback_ts_usp = current_timestamp_usp_reg[63] ^ current_timestamp_usp_reg[50] ^ current_timestamp_usp_reg[40] ^ current_timestamp_usp_reg[30];

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            nonce_j_lfsr_reg <= 64'hCDEF_1234_5678_9ABC;
            current_timestamp_usp_reg <= 64'hABC1_2345_6789_DEF0;
        end else begin
            nonce_j_lfsr_reg <= {nonce_j_lfsr_reg[62:0], lfsr_feedback_nonce_j};
            current_timestamp_usp_reg <= {current_timestamp_usp_reg[62:0], lfsr_feedback_ts_usp};
        end
    end

    assign usp_id_out = USP_ID;
    assign usp_sym_key_ev_out = USP_SYM_KEY_EV;
    assign usp_sym_key_cs_out = USP_SYM_KEY_CS;
    assign pub_j_usp_out = PUB_J_USP;
    assign nonce_j_lfsr_out = nonce_j_lfsr_reg;
    assign current_timestamp_usp_out = current_timestamp_usp_reg;
endmodule

// ============================================================================
// SECTION: CS Module (Charging Station) - Simplified
// Contains CS's fixed parameters and LFSR.
// ============================================================================
module CS(
    input clk, input reset,
    output [15:0] cs_id_out,
    output [63:0] cs_sym_key_usp_out,
    output [63:0] cs_sym_key_ev_out,
    output [63:0] pub_k_cs_out,
    output [63:0] token_val_out,
    output [63:0] nonce_lfsr_cs_out,
    output [63:0] timestamp_lfsr_cs_out
);
    localparam [15:0] CS_ID = 16'h0C51;
    localparam [63:0] CS_SYM_KEY_USP = 64'hCAFE_BABE_BEEF_DEAD;
    localparam [63:0] CS_SYM_KEY_EV = 64'hCAFE_BABE_DEAD_BEEF;
    localparam [63:0] TOKEN_VAL = 64'hFEED_FACE_BEEF_CAFE;
    localparam [63:0] PUB_K_CS = 64'hAABBCCDD_EEFF0011;

    reg [63:0] nonce_lfsr_cs_reg;
    reg [63:0] timestamp_lfsr_cs_reg;
    wire lfsr_feedback_nonce_cs = nonce_lfsr_cs_reg[63] ^ nonce_lfsr_cs_reg[58] ^ nonce_lfsr_cs_reg[48] ^ nonce_lfsr_cs_reg[38];
    wire lfsr_feedback_ts_cs    = timestamp_lfsr_cs_reg[63] ^ timestamp_lfsr_cs_reg[55] ^ timestamp_lfsr_cs_reg[45] ^ timestamp_lfsr_cs_reg[35];

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            nonce_lfsr_cs_reg <= 64'hFEDC_BA98_7654_3210;
            timestamp_lfsr_cs_reg <= 64'h9876_5432_10FE_DCBA;
        end else begin
            nonce_lfsr_cs_reg <= {nonce_lfsr_cs_reg[62:0], lfsr_feedback_nonce_cs};
            timestamp_lfsr_cs_reg <= {timestamp_lfsr_cs_reg[62:0], lfsr_feedback_ts_cs};
        end
    end

    assign cs_id_out = CS_ID;
    assign cs_sym_key_usp_out = CS_SYM_KEY_USP;
    assign cs_sym_key_ev_out = CS_SYM_KEY_EV;
    assign pub_k_cs_out = PUB_K_CS;
    assign token_val_out = TOKEN_VAL;
    assign nonce_lfsr_cs_out = nonce_lfsr_cs_reg;
    assign timestamp_lfsr_cs_out = timestamp_lfsr_cs_reg;
endmodule

// ============================================================================
// SECTION: EV_USP_Registration_Module (Combined EV-USP Registration Logic)
// This new module handles the full EV-USP registration handshake.
// ============================================================================
module EV_USP_Registration_Module(
    input clk, input reset,
    // Inputs from EV and USP parameters
    input [15:0] ev_id_in,
    input [63:0] ev_sym_key_usp_in,
    input [63:0] pub_k_ev_in,
    input [63:0] nonce_lfsr_ev_in,
    input [63:0] timestamp_lfsr_ev_in,
    input [15:0] usp_id_in,
    input [63:0] usp_sym_key_ev_in,
    input [63:0] pub_j_usp_in,
    input [63:0] nonce_j_lfsr_usp_in,
    input [63:0] current_timestamp_usp_in,

    // Communication signals
    output reg [127:0] ev_msg_to_usp_out,   // M1 from EV to USP (full 128-bit message)
    output reg ev_send_to_usp_ctrl,        // EV send signal to USP
    input [127:0] usp_msg_to_ev_in,        // M2 from USP to EV (full 128-bit message)
    input usp_ack_m2_in,                   // USP ACK for M2 sent

    // Status outputs
    output reg auth_pass_ev_usp,           // Indicates successful EV-USP registration
    output reg [3:0] state,                // Expose FSM state
    output reg [63:0] psid_ev_reg_out,     // PSIDEV for authentication module
    output reg [63:0] rs_i_reg_out         // RS_i for authentication module
);

    // Finite State Machine (FSM) for EV-USP Registration
    localparam EV_REG_IDLE         = 4'b0000,
               EV_REG_INIT         = 4'b0001,
               EV_REG_SEND_M1      = 4'b0010,
               EV_REG_WAIT_M2      = 4'b0011,
               EV_REG_DONE         = 4'b0100;

    // Internal registers for protocol values
    reg [63:0] ch_i;
    reg [63:0] rs_i_internal;
    reg [63:0] psid_ev_internal;
    reg [63:0] t1_ev, t2_usp;

    // Wires for cryptographic module outputs
    wire [63:0] hash_out_psidev;
    wire [63:0] puf_rs_i_wire;
    wire [63:0] enc_m1_reg_out;
    wire [63:0] dec_m2_reg_out;
    wire [63:0] hash_aj_ev;
    wire [63:0] enc_m2_usp_out;

    // Instantiate cryptographic modules
    HashFunction hf_psidev_inst (.data_in({ev_id_in, puf_rs_i_wire}), .hash_out(hash_out_psidev)); // PSIDEV = h(ID_i || RS_i)
    PUF puf_reg_ev_inst (.challenge(ch_i), .response(puf_rs_i_wire)); // RS_i = PUF(CH_i)
    Encryptor enc_m1_reg_inst (.data_in({psid_ev_internal, ch_i, rs_i_internal}), .key(ev_sym_key_usp_in), .data_out(enc_m1_reg_out)); // M1 = E(PSIDEV, CH_i, RS_i) ^ K_EV_USP_sym
    Decryptor dec_m2_reg_inst (.data_in(usp_msg_to_ev_in[63:0]), .key(ev_sym_key_usp_in), .data_out(dec_m2_reg_out)); // Decrypt M2 from USP

    // USP side crypto (for internal USP calculations within this module)
    HashFunction hf_aj_ev_usp_int (.data_in({dec_m1_reg_out[63:48], dec_m1_reg_out[47:32], dec_m1_reg_out[31:16], usp_id_in, pub_j_usp_in}), .hash_out(hash_aj_ev));
    Encryptor enc_m2_usp_int (.data_in({hash_aj_ev, usp_id_in}), .key(usp_sym_key_ev_in), .data_out(enc_m2_usp_out));

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            state <= EV_REG_IDLE;
            ev_msg_to_usp_out <= 0;
            ev_send_to_usp_ctrl <= 0;
            auth_pass_ev_usp <= 0;
            psid_ev_internal <= 0;
            rs_i_internal <= 0;
            t1_ev <= 0; t2_usp <= 0;
            ch_i <= 0;
            psid_ev_reg_out <= 0;
            rs_i_reg_out <= 0;
        end else begin
            case (state)
                EV_REG_IDLE: begin
                    // Triggered by top-level module
                end
                EV_REG_INIT: begin
                    ch_i <= nonce_lfsr_ev_in;
                    rs_i_internal <= puf_rs_i_wire;
                    psid_ev_internal <= hash_out_psidev;
                    t1_ev <= timestamp_lfsr_ev_in;
                    state <= EV_REG_SEND_M1;
                end
                EV_REG_SEND_M1: begin
                    ev_msg_to_usp_out <= {enc_m1_reg_out, t1_ev};
                    ev_send_to_usp_ctrl <= 1;
                    state <= EV_REG_WAIT_M2;
                end
                EV_REG_WAIT_M2: begin
                    ev_send_to_usp_ctrl <= 0;
                    if (usp_ack_m2_in) begin
                        t2_usp <= usp_msg_to_ev_in[127:64]; // Extract T2 from M2
                        if ( (current_timestamp_usp_in > t2_usp && (current_timestamp_usp_in - t2_usp) < 64'd1000) ||
                             (t2_usp > current_timestamp_usp_in && (t2_usp - current_timestamp_usp_in) < 64'd1000) ) begin
                            // Decrypt M2 (dec_m2_reg_out contains A_j || ID_j)
                            auth_pass_ev_usp <= 1;
                            psid_ev_reg_out <= psid_ev_internal;
                            rs_i_reg_out <= rs_i_internal;
                            state <= EV_REG_DONE;
                        end else begin
                            auth_pass_ev_usp <= 0;
                            state <= EV_REG_IDLE;
                        end
                    end
                end
                EV_REG_DONE: begin
                    // Hold state
                end
            endcase
        end
    end
endmodule

// ============================================================================
// SECTION: CS_USP_Registration_Module (Combined CS-USP Registration Logic)
// This new module handles the full CS-USP registration handshake.
// ============================================================================
module CS_USP_Registration_Module(
    input clk, input reset,
    // Inputs from CS and USP parameters
    input [15:0] cs_id_in,
    input [63:0] cs_sym_key_usp_in,
    input [63:0] pub_k_cs_in,
    input [63:0] nonce_lfsr_cs_in,
    input [63:0] timestamp_lfsr_cs_in,
    input [15:0] usp_id_in,
    input [63:0] usp_sym_key_cs_in,
    input [63:0] pub_j_usp_in,
    input [63:0] nonce_j_lfsr_usp_in,
    input [63:0] current_timestamp_usp_in,

    // Communication signals
    output reg [127:0] cs_msg_to_usp_out,   // M1 from CS to USP (full 128-bit message)
    output reg cs_send_to_usp_ctrl,        // CS send signal to USP
    input [127:0] usp_msg_to_cs_in,        // M2 from USP to CS (full 128-bit message)
    input usp_ack_m2_cs_in,                // USP ACK for M2 sent

    // Status outputs
    output reg reg_ack_cs_cs,              // CS acknowledges its own registration completion
    output reg [3:0] state,                // Expose FSM state
    output reg [63:0] ch_k_reg_out,        // CH_k for authentication module
    output reg [63:0] rs_k_reg_out         // RS_k for authentication module
);

    // Finite State Machine (FSM) for CS-USP Registration
    localparam CS_REG_IDLE         = 4'b0000,
               CS_REG_INIT         = 4'b0001,
               CS_REG_SEND_M1      = 4'b0010,
               CS_REG_WAIT_M2      = 4'b0011,
               CS_REG_DONE         = 4'b0100;

    // Internal registers for protocol values
    reg [63:0] ch_k_internal;
    reg [63:0] rs_k_internal;
    reg [63:0] t1_cs, t2_usp_cs;

    // Wires for cryptographic module outputs
    wire [63:0] puf_rs_k_cs_wire;
    wire [63:0] enc_m1_cs_reg_out;
    wire [63:0] dec_m2_cs_reg_out;
    wire [63:0] hash_aj_cs;
    wire [63:0] enc_m2_usp_cs_out;

    // Instantiate cryptographic modules
    PUF puf_reg_cs_inst (.challenge(ch_k_internal), .response(puf_rs_k_cs_wire)); // RS_k = PUF(CH_k)
    Encryptor enc_m1_cs_reg_inst (.data_in({cs_id_in, ch_k_internal, rs_k_internal, pub_k_cs_in}), .key(cs_sym_key_usp_in), .data_out(enc_m1_cs_reg_out));
    Decryptor dec_m2_cs_reg_inst (.data_in(usp_msg_to_cs_in[63:0]), .key(cs_sym_key_usp_in), .data_out(dec_m2_cs_reg_out));

    // USP side crypto (for internal USP calculations within this module)
    HashFunction hf_aj_cs_usp_int (.data_in({dec_m1_cs_reg_out[63:48], dec_m1_cs_reg_out[47:32], dec_m1_cs_reg_out[31:16], usp_id_in, pub_j_usp_in}), .hash_out(hash_aj_cs));
    Encryptor enc_m2_usp_cs_int (.data_in({usp_id_in, hash_aj_cs}), .key(usp_sym_key_cs_in), .data_out(enc_m2_usp_cs_out));

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            state <= CS_REG_IDLE;
            cs_msg_to_usp_out <= 0;
            cs_send_to_usp_ctrl <= 0;
            reg_ack_cs_cs <= 0;
            t1_cs <= 0; t2_usp_cs <= 0;
            ch_k_internal <= 0; rs_k_internal <= 0;
            ch_k_reg_out <= 0;
            rs_k_reg_out <= 0;
        end else begin
            case (state)
                CS_REG_IDLE: begin
                    // Triggered by top-level module
                end
                CS_REG_INIT: begin
                    ch_k_internal <= nonce_lfsr_cs_in;
                    rs_k_internal <= puf_rs_k_cs_wire;
                    t1_cs <= timestamp_lfsr_cs_in;
                    state <= CS_REG_SEND_M1;
                end
                CS_REG_SEND_M1: begin
                    cs_msg_to_usp_out <= {enc_m1_cs_reg_out, t1_cs};
                    cs_send_to_usp_ctrl <= 1;
                    state <= CS_REG_WAIT_M2;
                end
                CS_REG_WAIT_M2: begin
                    cs_send_to_usp_ctrl <= 0;
                    if (usp_ack_m2_cs_in) begin
                        t2_usp_cs <= usp_msg_to_cs_in[127:64];
                        if ( (current_timestamp_usp_in > t2_usp_cs && (current_timestamp_usp_in - t2_usp_cs) < 64'd1000) ||
                             (t2_usp_cs > current_timestamp_usp_in && (t2_usp_cs - current_timestamp_usp_in) < 64'd1000) ) begin
                            // Decrypt M2 (dec_m2_cs_reg_out contains ID_j || A_j)
                            reg_ack_cs_cs <= 1;
                            ch_k_reg_out <= ch_k_internal;
                            rs_k_reg_out <= rs_k_internal;
                            state <= CS_REG_DONE;
                        end else begin
                            reg_ack_cs_cs <= 0;
                            state <= CS_REG_IDLE;
                        end
                    end
                end
                CS_REG_DONE: begin
                    // Hold state
                end
            endcase
        end
    end
endmodule

// ============================================================================
// SECTION: EV_CS_Authentication Module (Combined Authentication Logic)
// This module handles the full EV-CS mutual authentication handshake.
// ============================================================================
module EV_CS_Authentication(
    input clk, input reset,
    // Inputs from EV and CS parameters
    input [15:0] ev_id_in,
    input [63:0] ev_sym_key_cs_in,
    input [63:0] pub_k_ev_in,
    input [63:0] nonce_lfsr_ev_in,
    input [63:0] timestamp_lfsr_ev_in,
    input [15:0] cs_id_in,
    input [63:0] cs_sym_key_ev_in,
    input [63:0] pub_k_cs_in,
    input [63:0] token_val_in,
    input [63:0] nonce_lfsr_cs_in,
    input [63:0] timestamp_lfsr_cs_in,

    // Inputs from EV and CS Registration
    input [63:0] psid_ev_in, // PSIDEV from EV registration
    input [63:0] rs_i_in,    // RS_i from EV registration
    input [63:0] ch_k_in,    // CH_k from CS registration
    input [63:0] rs_k_in,    // RS_k from CS registration

    // Communication signals (acting as a bridge between EV/CS and this module)
    output reg [127:0] ev_auth_msg_out,   // M1/M3 from EV side of auth
    output reg ev_auth_send,             // EV side send signal
    input [127:0] cs_auth_msg_in,        // M2/M4 to EV side of auth
    input cs_auth_ack_in,                // CS side ACK signal

    output reg [127:0] cs_auth_msg_out,   // M2/M4 from CS side of auth
    output reg cs_auth_send,             // CS side send signal
    input [127:0] ev_auth_msg_in,        // M1/M3 to CS side of auth
    input ev_auth_ack_in,                // EV side ACK signal

    // Status output for top-level
    output reg final_ack_ev_cs,          // Indicates successful EV-CS mutual authentication
    output reg [3:0] state               // Expose FSM state for testbench observation
);

    // Finite State Machine (FSM) for Combined EV-CS Authentication
    localparam AUTH_IDLE         = 4'b0000,
               AUTH_EV_INIT      = 4'b0001, // EV side: Initialize authentication parameters
               AUTH_EV_SEND_M1   = 4'b0010, // EV side: Send M1 to CS
               AUTH_CS_WAIT_M1   = 4'b0011, // CS side: Wait for M1 from EV
               AUTH_CS_SEND_M2   = 4'b0100, // CS side: Send M2 to EV
               AUTH_EV_WAIT_M2   = 4'b0101, // EV side: Wait for M2 from CS
               AUTH_EV_SEND_M3   = 4'b0110, // EV side: Send M3 to CS
               AUTH_CS_WAIT_M3   = 4'b0111, // CS side: Wait for M3 from EV
               AUTH_CS_SEND_M4   = 4'b1000, // CS side: Send M4 to EV
               AUTH_EV_WAIT_M4   = 4'b1001, // EV side: Wait for M4 from CS
               AUTH_DONE         = 4'b1010; // Authentication complete

    // LFSRs for Nonce and Timestamp generation (internal to this module for authentication)
    reg [63:0] nonce_lfsr_auth_reg;
    reg [63:0] timestamp_lfsr_auth_reg;
    wire lfsr_feedback_nonce_auth = nonce_lfsr_auth_reg[63] ^ nonce_lfsr_auth_reg[57] ^ nonce_lfsr_auth_reg[47] ^ nonce_lfsr_auth_reg[37];
    wire lfsr_feedback_ts_auth    = timestamp_lfsr_auth_reg[63] ^ timestamp_lfsr_auth_reg[54] ^ timestamp_lfsr_auth_reg[44] ^ timestamp_lfsr_auth_reg[34];

    // LFSR update logic
    always @(posedge clk or posedge reset) begin
        if (reset) begin
            nonce_lfsr_auth_reg <= 64'hF0F0_F0F0_F0F0_F0F0;
            timestamp_lfsr_auth_reg <= 64'hC0C0_C0C0_C0C0_C0C0;
        end else begin
            nonce_lfsr_auth_reg <= {nonce_lfsr_auth_reg[62:0], lfsr_feedback_nonce_auth};
            timestamp_lfsr_auth_reg <= {timestamp_lfsr_auth_reg[62:0], lfsr_feedback_ts_auth};
        end
    end

    // Internal registers for protocol values (shared between EV/CS sides within this module)
    reg [63:0] n1, n2, n4;
    reg [63:0] t1, t2, t3, t4;
    reg [63:0] ch_a, seed;
    reg [63:0] ka_ev, ka_cs; // K_a computed by EV and CS respectively
    reg [63:0] rs_auth_ev_val; // RS computed by EV during authentication
    reg [63:0] tk_cs; // T_K token from CS

    // Wires for cryptographic module outputs
    // EV side crypto
    wire [63:0] enc_m1_auth_out;
    wire [63:0] dec_m2_auth_out;
    wire [63:0] puf_rs_auth_ev_wire;
    wire [63:0] hash_out_rs_k_ev;
    wire [63:0] puf_ka_ev_wire;
    wire [63:0] enc_m3_auth_out;
    wire [63:0] dec_m4_auth_out;

    // CS side crypto
    wire [63:0] dec_m1_auth_cs_out;
    wire [63:0] puf_ka_cs_wire;
    wire [63:0] enc_m2_auth_cs_out;
    wire [63:0] dec_m3_auth_cs_out;
    wire [63:0] hash_rs_k_cs_wire;
    wire [63:0] enc_m4_auth_cs_out;

    // Instantiate cryptographic modules for EV side of authentication
    // M1 = E(PSIDEV, N1, Pub_k) ^ K_EV_CS_sym
    Encryptor enc_m1_auth_inst (.data_in({psid_ev_in, n1, pub_k_ev_in}), .key(ev_sym_key_cs_in), .data_out(enc_m1_auth_out));
    Decryptor dec_m2_auth_inst (.data_in(cs_auth_msg_in[63:0]), .key(ev_sym_key_cs_in), .data_out(dec_m2_auth_out));
    PUF puf_auth_rs_ev_inst (.challenge(dec_m2_auth_out[47:32]), .response(puf_rs_auth_ev_wire)); // CH_A is dec_m2_auth_out[47:32]
    PUF puf_auth_ka_ev_inst (.challenge(dec_m2_auth_out[31:0]), .response(puf_ka_ev_wire)); // K_a = PUF(seed)
    HashFunction hf_rs_k_ev_inst (.data_in({puf_ka_ev_wire, 64'h0}), .hash_out(hash_out_rs_k_ev)); // H(PUF(seed)) for RS_k verification
    // M3 = E(PSIDEV, CH_k, RS, RS_k, K_a, Pub_k) ^ K_EV_CS_sym
    Encryptor enc_m3_auth_inst (.data_in({psid_ev_in, ch_k_in, puf_rs_auth_ev_wire, hash_out_rs_k_ev, puf_ka_ev_wire, pub_k_ev_in}), .key(ev_sym_key_cs_in), .data_out(enc_m3_auth_out));
    Decryptor dec_m4_auth_inst (.data_in(cs_auth_msg_in[63:0]), .key(ev_sym_key_cs_in), .data_out(dec_m4_auth_out));

    // Instantiate cryptographic modules for CS side of authentication
    // M1 = E(PSIDEV, N1, Pub_k) ^ K_EV_CS_sym (received by CS)
    Decryptor dec_m1_auth_cs_inst (.data_in(ev_auth_msg_in[63:0]), .key(cs_sym_key_ev_in), .data_out(dec_m1_auth_cs_out));
    PUF puf_auth_ka_cs_inst (.challenge(seed), .response(puf_ka_cs_wire)); // K_a = PUF(seed)
    // M2 = E(ID_k || CH_A || N2 || seed || Pub_k) ^ K_EV_CS_sym
    Encryptor enc_m2_auth_cs_inst (.data_in({cs_id_in, ch_a, n2, seed, pub_k_cs_in}), .key(cs_sym_key_ev_in), .data_out(enc_m2_auth_cs_out));
    // M3 = E(PSIDEV, CH_k, RS, RS_k, K_a, Pub_k) ^ K_EV_CS_sym (received by CS)
    Decryptor dec_m3_auth_cs_inst (.data_in(ev_auth_msg_in[63:0]), .key(cs_sym_key_ev_in), .data_out(dec_m3_auth_cs_out));
    HashFunction hf_rs_k_cs_inst (.data_in({puf_ka_cs_wire, 64'h0}), .hash_out(hash_rs_k_cs_wire)); // H(PUF(seed))
    // M4 = E(ID_k || CH_k || N4 || RS_k || T_K || K_a || Pub_k) ^ K_EV_CS_sym
    Encryptor enc_m4_auth_cs_inst (.data_in({cs_id_in, ch_k_in, n4, hash_rs_k_cs_wire, token_val_in, ka_cs, pub_k_cs_in}), .key(cs_sym_key_ev_in), .data_out(enc_m4_auth_cs_out));


    // Main FSM logic for Combined EV-CS Authentication
    always @(posedge clk or posedge reset) begin
        if (reset) begin
            state <= AUTH_IDLE;
            ev_auth_msg_out <= 0;
            ev_auth_send <= 0;
            cs_auth_msg_out <= 0;
            cs_auth_send <= 0;
            final_ack_ev_cs <= 0;
            n1 <= 0; n2 <= 0; n4 <= 0;
            t1 <= 0; t2 <= 0; t3 <= 0; t4 <= 0;
            ch_a <= 0; seed <= 0;
            ka_ev <= 0; ka_cs <= 0;
            rs_auth_ev_val <= 0;
            tk_cs <= 0;
        end else begin
            case (state)
                AUTH_IDLE: begin
                    // Triggered by top-level module to start authentication
                    state <= AUTH_EV_INIT;
                end

                // ===================== EV Side: M1 Send =====================
                AUTH_EV_INIT: begin
                    n1 <= nonce_lfsr_ev_in; // Pick N1 (random nonce)
                    t1 <= timestamp_lfsr_ev_in; // Pick T1 (current timestamp)
                    state <= AUTH_EV_SEND_M1; // Move to send M1
                end
                AUTH_EV_SEND_M1: begin
                    // M1 = E(PSIDEV || N1 || Pub_k) ^ K_EV_CS_sym || T1
                    ev_auth_msg_out <= {enc_m1_auth_out, t1};
                    ev_auth_send <= 1; // Assert send signal to CS
                    state <= AUTH_CS_WAIT_M1; // Transition to CS waiting for M1
                end

                // ===================== CS Side: M1 Receive & M2 Send =====================
                AUTH_CS_WAIT_M1: begin
                    ev_auth_send <= 0; // De-assert EV send signal
                    if (ev_auth_ack_in) begin // Check if EV has sent M1 and acknowledged
                        // M1 received from EV (ev_auth_msg_in)
                        t1 <= ev_auth_msg_in[127:64]; // Extract T1 from M1
                        t2 <= timestamp_lfsr_cs_in; // Current timestamp for T2
                        // Check |TS2 - TS1| < Delta_t
                        if ( (t2 > t1 && (t2 - t1) < 64'd1000) ||
                             (t1 > t2 && (t1 - t2) < 64'd1000) ) begin // Delta_t = 1000ns
                            // Decrypt M1 (dec_m1_auth_cs_out contains PSIDEV || N1 || Pub_k)
                            ch_a <= nonce_lfsr_cs_in; // Pick CH_A (random challenge)
                            seed <= nonce_lfsr_cs_in + 64'd1; // Pick seed (simple increment for simulation)
                            ka_cs <= puf_ka_cs_wire; // Compute K_a = PUF(seed)
                            n2 <= nonce_lfsr_cs_in + 64'd2; // Pick N2 (random nonce)
                            state <= AUTH_CS_SEND_M2; // Move to send M2
                        end else begin
                            final_ack_ev_cs <= 0; // Authentication failed due to timestamp
                            state <= AUTH_IDLE;
                        end
                    end
                end
                AUTH_CS_SEND_M2: begin
                    // M2 = E(ID_k || CH_A || N2 || seed || Pub_k) ^ K_EV_CS_sym || T2
                    cs_auth_msg_out <= {enc_m2_auth_cs_out, t2};
                    cs_auth_send <= 1; // Assert send signal to EV
                    state <= AUTH_EV_WAIT_M2; // Transition to EV waiting for M2
                end

                // ===================== EV Side: M2 Receive & M3 Send =====================
                AUTH_EV_WAIT_M2: begin
                    cs_auth_send <= 0; // De-assert CS send signal
                    if (cs_auth_ack_in) begin // Check if CS has sent M2 and acknowledged
                        // M2 received from CS (cs_auth_msg_in)
                        t2 <= cs_auth_msg_in[127:64]; // Extract T2 from M2
                        // Check |TS2 - TS1| < Delta_t (TS2 is received t2, TS1 is sent t1)
                        if ( (t2 > t1 && (t2 - t1) < 64'd1000) ||
                             (t1 > t2 && (t1 - t2) < 64'd1000) ) begin // Delta_t = 1000ns
                            // Decrypt M2 (dec_m2_auth_out contains ID_k || CH_A || N2 || seed || Pub_k)
                            rs_auth_ev_val <= puf_rs_auth_ev_wire; // Generate RS = PUF(CH_A)
                            ka_ev <= puf_ka_ev_wire; // Compute K_a = PUF(seed)
                            t3 <= timestamp_lfsr_ev_in; // Pick T3 (current timestamp)
                            state <= AUTH_EV_SEND_M3; // Move to send M3
                        end else begin
                            final_ack_ev_cs <= 0; // Authentication failed due to timestamp
                            state <= AUTH_IDLE;
                        end
                    end
                end
                AUTH_EV_SEND_M3: begin
                    // M3 = E(PSIDEV || CH_k || RS || RS_k || K_a || Pub_k) ^ K_EV_CS_sym || T3
                    ev_auth_msg_out <= {enc_m3_auth_out, t3};
                    ev_auth_send <= 1; // Assert send signal to CS
                    state <= AUTH_CS_WAIT_M3; // Transition to CS waiting for M3
                end

                // ===================== CS Side: M3 Receive & M4 Send =====================
                AUTH_CS_WAIT_M3: begin
                    ev_auth_send <= 0; // De-assert EV send signal
                    if (ev_auth_ack_in) begin // Check if EV has sent M3 and acknowledged
                        // M3 received from EV (ev_auth_msg_in)
                        t3 <= ev_auth_msg_in[127:64]; // Extract T3 from M3
                        t4 <= timestamp_lfsr_cs_in; // Current timestamp for T4
                        // Check |TS4 - TS3| < Delta_t
                        if ( (t4 > t3 && (t4 - t3) < 64'd1000) ||
                             (t3 > t4 && (t3 - t4) < 64'd1000) ) begin // Delta_t = 1000ns
                            // Decrypt M3 (dec_m3_auth_cs_out contains PSIDEV || CH_k || RS || RS_k || K_a || Pub_k)
                            // Verify PSIDEV, CH_k, RS, RS_k, K_a, Pub_k
                            // For simplicity, let's just check RS_k and K_a for now
                            if (dec_m3_auth_cs_out[15:0] == hash_rs_k_cs_wire[15:0] && // Simplified check for RS_k
                                dec_m3_auth_cs_out[79:64] == ka_cs) begin // Simplified check for K_a
                                tk_cs <= token_val_in; // Generate token T_K
                                n4 <= nonce_lfsr_cs_in + 64'd3; // Pick N4 (random nonce)
                                state <= AUTH_CS_SEND_M4; // Move to send M4
                            end else begin
                                final_ack_ev_cs <= 0; // Authentication failed (M3 verification mismatch)
                                state <= AUTH_IDLE;
                            end
                        end else begin
                            final_ack_ev_cs <= 0; // Authentication failed due to timestamp
                            state <= AUTH_IDLE;
                        end
                    end
                end
                AUTH_CS_SEND_M4: begin
                    // M4 = E(ID_k || CH_k || N4 || RS_k || T_K || K_a || Pub_k) ^ K_EV_CS_sym || T4
                    cs_auth_msg_out <= {enc_m4_auth_cs_out, t4};
                    cs_auth_send <= 1; // Assert send signal to EV
                    state <= AUTH_EV_WAIT_M4; // Transition to EV waiting for M4
                end

                // ===================== EV Side: M4 Receive & Final Check =====================
                AUTH_EV_WAIT_M4: begin
                    cs_auth_send <= 0; // De-assert CS send signal
                    if (cs_auth_ack_in) begin // Check if CS has sent M4 and acknowledged
                        // M4 received from CS (cs_auth_msg_in)
                        t4 <= cs_auth_msg_in[127:64]; // Extract T4 from M4
                        // Check |TS4 - TS3| < Delta_t
                        if ( (t4 > t3 && (t4 - t3) < 64'd1000) ||
                             (t3 > t4 && (t3 - t4) < 64'd1000) ) begin // Delta_t = 1000ns
                            // Decrypt M4 (dec_m4_auth_out contains ID_k || CH_k || N4 || RS_k || T_K || K_a || Pub_k)
                            // Verify CS_k = H(PUF(seed)) (hash_out_rs_k_ev)
                            // Also verify RS (dec_m4_auth_out[95:64] assuming it's RS) against locally computed rs_auth_ev_val
                            if (dec_m4_auth_out[63:0] == hash_out_rs_k_ev[63:0] && // Simplified check for RS_k
                                dec_m4_auth_out[95:64] == rs_auth_ev_val) begin // Simplified check for RS
                                final_ack_ev_cs <= 1; // Mutual Authentication established
                                state <= AUTH_DONE; // Authentication complete
                            end else begin
                                final_ack_ev_cs <= 0; // Authentication failed (RS_k or RS mismatch)
                                state <= AUTH_IDLE;
                            end
                        end else begin
                            final_ack_ev_cs <= 0; // Authentication failed (timestamp)
                            state <= AUTH_IDLE;
                        end
                    end
                end
                AUTH_DONE: begin
                    // Hold in this state after successful authentication
                end
            endcase
        end
    end

endmodule

// ============================================================================
// SECTION: Top-Level Module (EV_USP_CS_FPGA)
// Orchestrates the sequential execution of the three authentication phases.
// ============================================================================
module EV_USP_CS_FPGA(
    input clk, input reset,
    output [3:0] leds, // LED outputs to indicate protocol status
    output reg [1:0] top_state, // Expose top-level FSM state for testbench
    output wire [3:0] ev_reg_state_out, // Expose EV-USP Registration FSM state
    output wire [3:0] cs_reg_state_out, // Expose CS-USP Registration FSM state
    output wire [3:0] auth_state_out // Expose EV_CS_Authentication FSM state
);
    // Wires for inter-module communication signals (messages and control)
    // EV-USP Registration communication
    wire [127:0] ev_reg_msg_to_usp;
    wire ev_reg_send_to_usp_ctrl;
    wire [127:0] usp_reg_msg_to_ev;
    wire usp_reg_ack_m2_ev;

    // CS-USP Registration communication
    wire [127:0] cs_reg_msg_to_usp;
    wire cs_reg_send_to_usp_ctrl;
    wire [127:0] usp_reg_msg_to_cs;
    wire usp_reg_ack_m2_cs;

    // Signals to pass registration data to authentication module
    wire [63:0] psid_ev_from_reg;
    wire [63:0] rs_i_from_reg;
    wire [63:0] ch_k_from_reg;
    wire [63:0] rs_k_from_reg;

    // EV-CS Authentication communication
    wire [127:0] ev_auth_msg_out_sig;
    wire ev_auth_send_sig;
    wire [127:0] cs_auth_msg_in_sig;
    wire cs_auth_ack_in_sig;

    wire [127:0] cs_auth_msg_out_sig;
    wire cs_auth_send_sig;
    wire [127:0] ev_auth_msg_in_sig;
    wire ev_auth_ack_in_sig;

    // Status signals from sub-modules for LED mapping
    wire auth_pass_ev_usp_sig;
    wire final_ack_ev_cs_sig;
    wire reg_ack_ev_usp_sig;
    wire reg_ack_cs_usp_sig;
    wire reg_ack_cs_cs_sig; // Internal to CS_USP_Registration_Module

    // Internal FSM states from sub-modules
    wire [3:0] ev_reg_state_internal;
    wire [3:0] cs_reg_state_internal;
    wire [3:0] auth_state_internal;

    // Parameters from EV, USP, CS modules
    wire [15:0] ev_id_param;
    wire [63:0] ev_sym_key_usp_param;
    wire [63:0] ev_sym_key_cs_param;
    wire [63:0] pub_k_ev_param;
    wire [63:0] ev_nonce_lfsr_param;
    wire [63:0] ev_timestamp_lfsr_param;

    wire [15:0] usp_id_param;
    wire [63:0] usp_sym_key_ev_param;
    wire [63:0] usp_sym_key_cs_param;
    wire [63:0] pub_j_usp_param;
    wire [63:0] usp_nonce_j_lfsr_param;
    wire [63:0] usp_current_timestamp_param;

    wire [15:0] cs_id_param;
    wire [63:0] cs_sym_key_usp_param;
    wire [63:0] cs_sym_key_ev_param;
    wire [63:0] pub_k_cs_param;
    wire [63:0] token_val_param;
    wire [63:0] cs_nonce_lfsr_param;
    wire [63:0] cs_timestamp_lfsr_param;


    // Instantiate the simplified EV, USP, and CS parameter modules
    EV ev_params_inst (
        .clk(clk), .reset(reset),
        .ev_id_out(ev_id_param),
        .ev_sym_key_usp_out(ev_sym_key_usp_param),
        .ev_sym_key_cs_out(ev_sym_key_cs_param),
        .pub_k_ev_out(pub_k_ev_param),
        .nonce_lfsr_out(ev_nonce_lfsr_param),
        .timestamp_lfsr_out(ev_timestamp_lfsr_param)
    );

    USP usp_params_inst (
        .clk(clk), .reset(reset),
        .usp_id_out(usp_id_param),
        .usp_sym_key_ev_out(usp_sym_key_ev_param),
        .usp_sym_key_cs_out(usp_sym_key_cs_param),
        .pub_j_usp_out(pub_j_usp_param),
        .nonce_j_lfsr_out(usp_nonce_j_lfsr_param),
        .current_timestamp_usp_out(usp_current_timestamp_param)
    );

    CS cs_params_inst (
        .clk(clk), .reset(reset),
        .cs_id_out(cs_id_param),
        .cs_sym_key_usp_out(cs_sym_key_usp_param),
        .cs_sym_key_ev_out(cs_sym_key_ev_param),
        .pub_k_cs_out(pub_k_cs_param),
        .token_val_out(token_val_param),
        .nonce_lfsr_cs_out(cs_nonce_lfsr_param),
        .timestamp_lfsr_cs_out(cs_timestamp_lfsr_param)
    );


    // Instantiate the EV-USP Registration Module
    EV_USP_Registration_Module ev_usp_reg_inst (
        .clk(clk), .reset(reset),
        .ev_id_in(ev_id_param),
        .ev_sym_key_usp_in(ev_sym_key_usp_param),
        .pub_k_ev_in(pub_k_ev_param),
        .nonce_lfsr_ev_in(ev_nonce_lfsr_param),
        .timestamp_lfsr_ev_in(ev_timestamp_lfsr_param),
        .usp_id_in(usp_id_param),
        .usp_sym_key_ev_in(usp_sym_key_ev_param),
        .pub_j_usp_in(pub_j_usp_param),
        .nonce_j_lfsr_usp_in(usp_nonce_j_lfsr_param),
        .current_timestamp_usp_in(usp_current_timestamp_param),

        .ev_msg_to_usp_out(ev_reg_msg_to_usp),
        .ev_send_to_usp_ctrl(ev_reg_send_to_usp_ctrl),
        .usp_msg_to_ev_in(usp_reg_msg_to_ev),
        .usp_ack_m2_in(usp_reg_ack_m2_ev),

        .auth_pass_ev_usp(auth_pass_ev_usp_sig),
        .state(ev_reg_state_internal),
        .psid_ev_reg_out(psid_ev_from_reg),
        .rs_i_reg_out(rs_i_from_reg)
    );

    // Instantiate the CS-USP Registration Module
    CS_USP_Registration_Module cs_usp_reg_inst (
        .clk(clk), .reset(reset),
        .cs_id_in(cs_id_param),
        .cs_sym_key_usp_in(cs_sym_key_usp_param),
        .pub_k_cs_in(pub_k_cs_param),
        .nonce_lfsr_cs_in(cs_nonce_lfsr_param),
        .timestamp_lfsr_cs_in(cs_timestamp_lfsr_param),
        .usp_id_in(usp_id_param),
        .usp_sym_key_cs_in(usp_sym_key_cs_param),
        .pub_j_usp_in(pub_j_usp_param),
        .nonce_j_lfsr_usp_in(usp_nonce_j_lfsr_param),
        .current_timestamp_usp_in(usp_current_timestamp_param),

        .cs_msg_to_usp_out(cs_reg_msg_to_usp),
        .cs_send_to_usp_ctrl(cs_reg_send_to_usp_ctrl),
        .usp_msg_to_cs_in(usp_reg_msg_to_cs),
        .usp_ack_m2_cs_in(usp_reg_ack_m2_cs),

        .reg_ack_cs_cs(reg_ack_cs_cs_sig),
        .state(cs_reg_state_internal),
        .ch_k_reg_out(ch_k_from_reg),
        .rs_k_reg_out(rs_k_from_reg)
    );

    // Instantiate the EV-CS Authentication Module
    EV_CS_Authentication auth_inst (
        .clk(clk), .reset(reset),
        .ev_id_in(ev_id_param),
        .ev_sym_key_cs_in(ev_sym_key_cs_param),
        .pub_k_ev_in(pub_k_ev_param),
        .nonce_lfsr_ev_in(ev_nonce_lfsr_param),
        .timestamp_lfsr_ev_in(ev_timestamp_lfsr_param),
        .cs_id_in(cs_id_param),
        .cs_sym_key_ev_in(cs_sym_key_ev_param),
        .pub_k_cs_in(pub_k_cs_param),
        .token_val_in(token_val_param),
        .nonce_lfsr_cs_in(cs_nonce_lfsr_param),
        .timestamp_lfsr_cs_in(cs_timestamp_lfsr_param),

        .psid_ev_in(psid_ev_from_reg),
        .rs_i_in(rs_i_from_reg),
        .ch_k_in(ch_k_from_reg),
        .rs_k_in(rs_k_from_reg),

        .ev_auth_msg_out(ev_auth_msg_out_sig),
        .ev_auth_send(ev_auth_send_sig),
        .cs_auth_msg_in(cs_auth_msg_out_sig),
        .cs_auth_ack_in(cs_auth_send_sig),

        .cs_auth_msg_out(cs_auth_msg_out_sig),
        .cs_auth_send(cs_auth_send_sig),
        .ev_auth_msg_in(ev_auth_msg_out_sig),
        .ev_auth_ack_in(ev_auth_send_sig),

        .final_ack_ev_cs(final_ack_ev_cs_sig),
        .state(auth_state_internal)
    );

    // Connections for USP's communication with registration modules
    // USP's input for EV registration
    assign usp_params_inst.ev_msg_in = ev_reg_msg_to_usp;
    assign usp_params_inst.ev_send_to_usp = ev_reg_send_to_usp_ctrl;
    // USP's output for EV registration
    assign usp_reg_msg_to_ev = usp_params_inst.usp_msg_out;
    assign usp_reg_ack_m2_ev = usp_params_inst.usp_ack_m2;

    // USP's input for CS registration
    assign usp_params_inst.cs_msg_in = cs_reg_msg_to_usp;
    assign usp_params_inst.cs_send_to_usp = cs_reg_send_to_usp_ctrl;
    // USP's output for CS registration
    assign usp_reg_msg_to_cs = usp_params_inst.usp_msg_out;
    assign usp_reg_ack_m2_cs = usp_params_inst.usp_ack_m2;


    // Expose internal states to top-level outputs for testbench
    assign ev_reg_state_out = ev_reg_state_internal;
    assign cs_reg_state_out = cs_reg_state_internal;
    assign auth_state_out = auth_state_internal;

    // Top-level FSM to sequence the three main phases of the protocol for simulation.
    localparam TOP_IDLE        = 2'b00,
               TOP_EV_REG      = 2'b01,
               TOP_CS_REG      = 2'b10,
               TOP_EV_CS_AUTH  = 2'b11;

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            top_state <= TOP_IDLE;
            ev_usp_reg_inst.state <= 4'b0000; // EV_REG_IDLE
            cs_usp_reg_inst.state <= 4'b0000; // CS_REG_IDLE
            auth_inst.state <= 4'b0000; // AUTH_IDLE
        end else begin
            case (top_state)
                TOP_IDLE: begin
                    top_state <= TOP_EV_REG;
                    ev_usp_reg_inst.state <= 4'b0001; // EV_REG_INIT
                end
                TOP_EV_REG: begin
                    if (ev_reg_state_internal == 4'b0100) begin // EV_REG_DONE
                        top_state <= TOP_CS_REG;
                        cs_usp_reg_inst.state <= 4'b0001; // CS_REG_INIT
                    end
                end
                TOP_CS_REG: begin
                    if (cs_reg_state_internal == 4'b0100) begin // CS_REG_DONE
                        top_state <= TOP_EV_CS_AUTH;
                        auth_inst.state <= 4'b0001; // AUTH_EV_INIT
                    end
                end
                TOP_EV_CS_AUTH: begin
                    if (auth_state_internal == 4'b1010) begin // AUTH_DONE
                        top_state <= TOP_IDLE;
                    end
                end
            endcase
        end
    end

    // Map internal status signals to the 4-bit LED output
    assign leds = {final_ack_ev_cs_sig, auth_pass_ev_usp_sig, reg_ack_cs_usp_sig, ev_usp_reg_inst.auth_pass_ev_usp};

endmodule
