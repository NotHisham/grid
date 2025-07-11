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
// and use XOR operations, not robust cryptographic algorithms.
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
// SECTION: EV Module (Electric Vehicle)
// Implements the EV's role in both registration with USP and authentication with CS.
// ============================================================================
module EV(
    input clk, input reset,
    // External interfaces (to USP and CS)
    output reg [63:0] ev_msg_out,       // Message M1/M3 sent from EV (only data part)
    output reg ev_send_to_usp,          // Control signal: EV sends M1 for registration to USP
    output reg ev_send_to_cs,           // Control signal: EV sends M1/M3 for authentication to CS
    input [63:0] usp_msg_in,            // Message M2 received from USP (only data part)
    input [63:0] cs_msg_in,             // Message M2/M4 received from CS (only data part)
    input usp_ack_m2,                   // Acknowledgment from USP that M2 was sent
    input cs_ack_m2_m4,                 // Acknowledgment from CS that M2/M4 was sent
    // Internal status outputs (for LEDs/top-level monitoring)
    output reg auth_pass_ev_usp,        // Indicates successful EV-USP registration/authentication
    output reg final_ack_ev_cs,          // Indicates successful EV-CS mutual authentication
    output reg [3:0] state              // Expose FSM state for testbench observation
);

    // EV's fixed ID and symmetric keys for communication
    localparam [15:0] EV_ID = 16'h00EF; // Unique identifier for this Electric Vehicle
    reg [63:0] EV_SYM_KEY_USP = 64'hDEAD_BEEF_CAFE_BABE; // Pre-shared symmetric key with USP
    reg [63:0] EV_SYM_KEY_CS = 64'hCAFE_BABE_DEAD_BEEF; // Pre-shared symmetric key with CS

    // Finite State Machine (FSM) for EV's protocol execution
    // localparam for states are still internal, but 'state' register is now an output.
    localparam EV_IDLE             = 4'b0000,          // Initial state, waiting for trigger
               // EV-USP Registration States (Table 1)
               EV_REG_INIT         = 4'b0001,          // Initialize registration parameters
               EV_REG_SEND_M1      = 4'b0010,          // Send M1 to USP
               EV_REG_WAIT_M2      = 4'b0011,          // Wait for M2 from USP
               EV_REG_DONE         = 4'b0100,          // EV-USP registration complete
               // EV-CS Authentication States (Table 2)
               EV_AUTH_INIT        = 4'b0101,          // Initialize authentication parameters
               EV_AUTH_SEND_M1     = 4'b0110,          // Send M1 to CS
               EV_AUTH_WAIT_M2     = 4'b0111,          // Wait for M2 from CS
               EV_AUTH_SEND_M3     = 4'b1000,          // Send M3 to CS
               EV_AUTH_WAIT_M4     = 4'b1001,          // Wait for M4 from CS
               EV_AUTH_DONE        = 4'b1010;          // EV-CS authentication complete

    // Linear Feedback Shift Registers (LFSRs) for Nonce and Timestamp generation
    // These generate pseudo-random sequences for freshness and uniqueness.
    reg [63:0] nonce_lfsr;     // For N1, CH_i
    reg [63:0] timestamp_lfsr; // For T1, T3, and local time checks
    wire lfsr_feedback_nonce = nonce_lfsr[63] ^ nonce_lfsr[61] ^ nonce_lfsr[60] ^ nonce_lfsr[59];
    wire lfsr_feedback_ts    = timestamp_lfsr[63] ^ timestamp_lfsr[53] ^ timestamp_lfsr[43] ^ timestamp_lfsr[33];

    // LFSR update logic: on clock edge or reset
    always @(posedge clk or posedge reset) begin
        if (reset) begin
            nonce_lfsr <= 64'hACE1_ACE1_ACE1_ACE1;       // Initial seed for nonce LFSR
            timestamp_lfsr <= 64'h1A2B_3C4D_5E6F_7A8B;   // Initial seed for timestamp LFSR
        end else begin
            nonce_lfsr <= {nonce_lfsr[62:0], lfsr_feedback_nonce};
            timestamp_lfsr <= {timestamp_lfsr[62:0], lfsr_feedback_ts};
        end
    end

    // Internal registers to hold protocol-specific values
    reg [63:0] ch_i;    // Challenge for PUF during registration (from EV)
    reg [63:0] rs_i;    // Response from PUF during registration (RS_i)
    reg [63:0] psid_ev; // Pseudonym ID for EV: h(ID_i || RS_i)
    reg [63:0] n1;      // Nonce N1 for authentication
    reg [63:0] t1, t2, t3, t4; // Timestamps for freshness checks

    // Wires for connecting instances of cryptographic modules
    wire [63:0] hash_out_psidev;    // Output of HashFunction for PSIDEV
    wire [63:0] puf_rs_i_wire;      // Output of PUF for RS_i (during registration)
    wire [63:0] enc_m1_reg_out;     // Encrypted M1 for USP registration
    wire [63:0] dec_m2_reg_out;     // Decrypted M2 from USP registration

    wire [63:0] hash_out_rs_k_ev;   // Output of HashFunction for H(PUF(seed)) on EV side
    wire [63:0] puf_ka_ev;          // Output of PUF for K_a in protocols
    wire [63:0] enc_m1_auth_out;    // Encrypted M1 for CS authentication
    wire [63:0] dec_m2_auth_out;    // Decrypted M2 from CS authentication
    wire [63:0] enc_m3_auth_out;    // Encrypted M3 for CS authentication
    wire [63:0] dec_m4_auth_out;    // Decrypted M4 from CS authentication

    // Instantiate cryptographic modules for EV's operations
    // EV-USP Registration related crypto
    HashFunction hf_psidev (.data_in({EV_ID, puf_rs_i_wire}), .hash_out(hash_out_psidev)); // PSIDEV = h(ID_i || RS_i)
    PUF puf_reg_ev (.challenge(ch_i), .response(puf_rs_i_wire)); // RS_i = PUF(CH_i)
    Encryptor enc_m1_reg (.data_in({psid_ev, ch_i, rs_i}), .key(EV_SYM_KEY_USP), .data_out(enc_m1_reg_out)); // M1 = E(PSIDEV, CH_i, RS_i) ^ K_EV_USP_sym
    Decryptor dec_m2_reg (.data_in(usp_msg_in), .key(EV_SYM_KEY_USP), .data_out(dec_m2_reg_out)); // Decrypt M2 from USP

    // EV-CS Authentication related crypto
    Encryptor enc_m1_auth (.data_in({psid_ev, n1}), .key(EV_SYM_KEY_CS), .data_out(enc_m1_auth_out)); // M1 = E(PSIDEV, N1) ^ K_EV_CS_sym
    Decryptor dec_m2_auth (.data_in(cs_msg_in), .key(EV_SYM_KEY_CS), .data_out(dec_m2_auth_out)); // Decrypt M2 from CS
    // M3 = E(PSIDEV, CH_k, RS, RS_k, K_a) ^ K_EV_CS_sym
    // Note: CH_k (dec_m2_auth_out[47:32]), RS (puf_rs_i_wire), RS_k (hash_out_rs_k_ev), K_a (puf_ka_ev)
    Encryptor enc_m3_auth (.data_in({psid_ev, dec_m2_auth_out[47:32], puf_rs_i_wire, hash_out_rs_k_ev, puf_ka_ev}), .key(EV_SYM_KEY_CS), .data_out(enc_m3_auth_out));
    Decryptor dec_m4_auth (.data_in(cs_msg_in), .key(EV_SYM_KEY_CS), .data_out(dec_m4_auth_out)); // Decrypt M4 from CS

    // PUF and Hash for K_a and H(PUF(seed)) during authentication
    PUF puf_auth_ka_ev (.challenge(dec_m2_auth_out[31:0]), .response(puf_ka_ev)); // K_a = PUF(seed) where seed is from M2
    HashFunction hf_rs_k_ev (.data_in({puf_ka_ev, 64'h0}), .hash_out(hash_out_rs_k_ev)); // H(PUF(seed)) for RS_k verification (added 64'h0 to match 128-bit input)

    // Main FSM logic for EV
    always @(posedge clk or posedge reset) begin
        if (reset) begin // Asynchronous reset
            state <= EV_IDLE;
            ev_msg_out <= 0;
            ev_send_to_usp <= 0;
            ev_send_to_cs <= 0;
            auth_pass_ev_usp <= 0;
            final_ack_ev_cs <= 0;
            psid_ev <= 0; // Clear PSIDEV on reset
            t1 <= 0; t2 <= 0; t3 <= 0; t4 <= 0; // Clear timestamps
            ch_i <= 0; rs_i <= 0; n1 <= 0; // Clear internal protocol values
        end else begin
            case (state)
                EV_IDLE: begin
                    // This state is managed by the top-level module (EV_USP_CS_FPGA)
                    // It will transition EV to EV_REG_INIT or EV_AUTH_INIT
                    // based on the overall protocol sequence.
                end

                // ===================== PHASE 1: EV -> USP Registration (Table 1) =====================
                EV_REG_INIT: begin
                    ch_i <= nonce_lfsr; // Pick CH_i (random challenge for PUF)
                    rs_i <= puf_rs_i_wire;   // Compute RS_i = PUF(CH_i)
                    psid_ev <= hash_out_psidev; // Compute PSIDEV = h(ID_i || RS_i)
                    t1 <= timestamp_lfsr; // Pick T1 (current timestamp)
                    state <= EV_REG_SEND_M1; // Move to send M1
                end
                EV_REG_SEND_M1: begin
                    // M1 = E(PSIDEV || CH_i || RS_i) ^ K_EV_USP_sym || T1
                    // Concatenate encrypted data and timestamp for message output
                    ev_msg_out <= {enc_m1_reg_out, t1};
                    ev_send_to_usp <= 1; // Assert send signal to USP
                    state <= EV_REG_WAIT_M2; // Wait for M2 from USP
                end
                EV_REG_WAIT_M2: begin
                    ev_send_to_usp <= 0; // De-assert send signal
                    if (usp_ack_m2) begin // Check if USP has sent M2 and acknowledged
                        // M2 received from USP (usp_msg_in)
                        t2 <= usp_msg_in; // Extract T2 from M2 (assuming M2 is E(Aj, IDj) || T2)
                        // Check |TS3 - TS2| < Delta_t (TS3 is current timestamp_lfsr, TS2 is received t2)
                        if ( (timestamp_lfsr > t2 && (timestamp_lfsr - t2) < 64'd1000) ||
                             (t2 > timestamp_lfsr && (t2 - timestamp_lfsr) < 64'd1000) ) begin // Delta_t = 1000ns for freshness
                            // Decrypt M2 (dec_m2_reg_out contains A_j || ID_j)
                            // Store A_j and ID_j (dec_m2_reg_out[63:32] is A_j, dec_m2_reg_out[31:0] is ID_j)
                            auth_pass_ev_usp <= 1; // EV successfully registered with USP
                            state <= EV_REG_DONE; // Registration complete
                        end else begin
                            // Timestamp check failed, re-initiate or error (for simplicity, go to IDLE)
                            auth_pass_ev_usp <= 0;
                            state <= EV_IDLE;
                        end
                    end
                end
                EV_REG_DONE: begin
                    // Hold in this state until triggered by top-level module for authentication
                end

                // ===================== PHASE 3: EV -> CS Authentication (Table 2) =====================
                EV_AUTH_INIT: begin
                    n1 <= nonce_lfsr; // Pick N1 (random nonce)
                    t1 <= timestamp_lfsr; // Pick T1 (current timestamp)
                    state <= EV_AUTH_SEND_M1; // Move to send M1
                end
                EV_AUTH_SEND_M1: begin
                    // M1 = E(PSIDEV || N1) ^ K_EV_CS_sym || T1
                    ev_msg_out <= {enc_m1_auth_out, t1};
                    ev_send_to_cs <= 1; // Assert send signal to CS
                    state <= EV_AUTH_WAIT_M2; // Wait for M2 from CS
                end
                EV_AUTH_WAIT_M2: begin
                    ev_send_to_cs <= 0; // De-assert send signal
                    if (cs_ack_m2_m4) begin // Check if CS has sent M2 and acknowledged
                        // M2 received from CS (cs_msg_in)
                        t2 <= cs_msg_in; // Extract T2 from M2 (assuming M2 is E(ID_k, CH_A, N2, seed) || T2)
                        // Check |TS2 - TS1| < Delta_t (TS2 is received t2, TS1 is sent t1)
                        if ( (t2 > t1 && (t2 - t1) < 64'd1000) ||
                             (t1 > t2 && (t1 - t2) < 64'd1000) ) begin // Delta_t = 1000ns
                            // Decrypt M2 (dec_m2_auth_out contains ID_k || CH_A || N2 || seed)
                            // Generate RS = PUF(CH_A) (puf_rs_i_wire, where CH_A is dec_m2_auth_out[47:32])
                            // Compute K_a = PUF(seed) (puf_ka_ev, where seed is dec_m2_auth_out[31:0])
                            t3 <= timestamp_lfsr; // Pick T3 (current timestamp)
                            state <= EV_AUTH_SEND_M3; // Move to send M3
                        end else begin
                            final_ack_ev_cs <= 0; // Authentication failed due to timestamp
                            state <= EV_IDLE;
                        end
                    end
                end
                EV_AUTH_SEND_M3: begin
                    // M3 = E(PSIDEV || CH_k || RS || RS_k || K_a) ^ K_EV_CS_sym || T3
                    // Note: CH_k is not explicitly sent by CS in M2, assuming it's derived or a fixed value here.
                    // RS is puf_rs_i_wire, RS_k is hash_out_rs_k_ev, K_a is puf_ka_ev
                    ev_msg_out <= {enc_m3_auth_out, t3};
                    ev_send_to_cs <= 1; // Assert send signal to CS
                    state <= EV_AUTH_WAIT_M4; // Wait for M4 from CS
                end
                EV_AUTH_WAIT_M4: begin
                    ev_send_to_cs <= 0; // De-assert send signal
                    if (cs_ack_m2_m4) begin // Check if CS has sent M4 and acknowledged
                        // M4 received from CS (cs_msg_in)
                        t4 <= cs_msg_in; // Extract T4 from M4 (assuming M4 is E(ID_k, CH_k, N4, RS_k, T_K, K_a) || T4)
                        // Check |TS4 - TS3| < Delta_t (TS4 is received t4, TS3 is sent t3)
                        if ( (t4 > t3 && (t4 - t3) < 64'd1000) ||
                             (t3 > t4 && (t3 - t4) < 64'd1000) ) begin // Delta_t = 1000ns
                            // Decrypt M4 (dec_m4_auth_out)
                            // Checks RS, RS_k, authenticating EV
                            // Verify CS_k = H(PUF(seed)) (hash_out_rs_k_ev)
                            // Assuming RS_k is part of dec_m4_auth_out, compare it with locally computed hash_out_rs_k_ev
                            if (dec_m4_auth_out[63:0] == hash_out_rs_k_ev[63:0]) begin // Simplified check
                                final_ack_ev_cs <= 1; // Mutual Authentication established
                                state <= EV_AUTH_DONE; // Authentication complete
                            end else begin
                                final_ack_ev_cs <= 0; // Authentication failed (RS_k mismatch)
                                state <= EV_IDLE;
                            end
                        end else begin
                            final_ack_ev_cs <= 0; // Authentication failed (timestamp)
                            state <= EV_IDLE;
                        end
                    end
                end
                EV_AUTH_DONE: begin
                    // Hold in this state after successful authentication
                end
            endcase
        end
    end
endmodule

// ============================================================================
// SECTION: USP Module (Universal Service Provider)
// Handles registration requests from both EV and CS.
// ============================================================================
module USP(
    input clk, input reset,
    // External interfaces (from EV and CS)
    input [127:0] ev_msg_in,             // M1 from EV (for registration), includes timestamp
    input ev_send_to_usp,               // EV sending M1
    output reg [127:0] usp_msg_out,      // M2 to EV/CS (includes timestamp)
    output reg usp_ack_m2,              // USP acknowledges M2 sent
    input [127:0] cs_msg_in,             // M1 from CS (for registration), includes timestamp
    input cs_send_to_usp,               // CS sending M1
    // Internal status outputs (for LEDs/top-level monitoring)
    output reg reg_ack_ev_usp,          // EV registration acknowledged by USP
    output reg reg_ack_cs_usp,           // CS registration acknowledged by USP
    output reg [2:0] state              // Expose FSM state for testbench observation
);

    localparam [15:0] USP_ID = 16'h0C51; // USP's ID (ID_j)
    reg [63:0] USP_SYM_KEY_EV = 64'hDEAD_BEEF_CAFE_BABE; // Pre-shared symmetric key with EV
    reg [63:0] USP_SYM_KEY_CS = 64'hCAFE_BABE_BEEF_DEAD; // Pre-shared symmetric key with CS

    // Finite State Machine (FSM) for USP's protocol execution
    localparam USP_IDLE            = 3'b000,          // Initial state, waiting for requests
               // EV-USP Registration States (Table 1)
               USP_EV_REG_WAIT_M1  = 3'b001,          // Wait for M1 from EV
               USP_EV_REG_SEND_M2  = 3'b010,          // Send M2 to EV
               // CS-USP Registration States (Table 2)
               USP_CS_REG_WAIT_M1  = 3'b011,          // Wait for M1 from CS
               USP_CS_REG_SEND_M2  = 3'b100;          // Send M2 to CS

    // LFSR for Nonce generation (for Nonce_j) and current timestamp
    reg [63:0] nonce_j_lfsr;
    reg [63:0] current_timestamp_usp; // USP's internal timestamp
    wire lfsr_feedback_nonce_j = nonce_j_lfsr[63] ^ nonce_j_lfsr[51] ^ nonce_j_lfsr[41] ^ nonce_j_lfsr[31];
    wire lfsr_feedback_ts_usp = current_timestamp_usp[63] ^ current_timestamp_usp[50] ^ current_timestamp_usp[40] ^ current_timestamp_usp[30];

    // LFSR update logic
    always @(posedge clk or posedge reset) begin
        if (reset) begin
            nonce_j_lfsr <= 64'hCDEF_1234_5678_9ABC;
            current_timestamp_usp <= 64'hABC1_2345_6789_DEF0;
        end else begin
            nonce_j_lfsr <= {nonce_j_lfsr[62:0], lfsr_feedback_nonce_j};
            current_timestamp_usp <= {current_timestamp_usp[62:0], lfsr_feedback_ts_usp};
        end
    end

    // Internal registers to hold protocol-specific values
    reg [63:0] t1_ev_reg, t2_usp_reg; // Timestamps for EV Registration
    reg [63:0] t1_cs_reg, t2_usp_cs_reg; // Timestamps for CS Registration

    // USP's simplified databases for registered entities
    reg [15:0] registered_ev_id; // Stores ID_i from EV registration
    reg [63:0] registered_aj_cs; // Stores A_j from CS registration

    // Wires for connecting instances of cryptographic modules
    wire [63:0] dec_m1_ev_reg_out;  // Decrypted M1 from EV
    wire [63:0] hash_aj_ev;         // A_j for EV registration
    wire [63:0] enc_m2_ev_reg_out;  // Encrypted M2 for EV registration

    wire [63:0] dec_m1_cs_reg_out;  // Decrypted M1 from CS
    wire [63:0] hash_aj_cs;         // A_j for CS registration
    wire [63:0] enc_m2_cs_reg_out;  // Encrypted M2 for CS registration

    // Instantiate cryptographic modules for USP's operations
    // EV-USP Registration related crypto
    Decryptor dec_m1_ev_reg (.data_in(ev_msg_in[63:0]), .key(USP_SYM_KEY_EV), .data_out(dec_m1_ev_reg_out));
    // h(ID_i || CH_i || RS_i || ID_j || Pub_j) -> ID_i (dec_m1_ev_reg_out[63:48]), CH_i (dec_m1_ev_reg_out[47:32]), RS_i (dec_m1_ev_reg_out[31:0])
    HashFunction hf_aj_ev (.data_in({dec_m1_ev_reg_out[63:48], dec_m1_ev_reg_out[47:32], dec_m1_ev_reg_out[31:0], USP_ID, USP_SYM_KEY_EV}), .hash_out(hash_aj_ev));
    // E(A_j || ID_j) ^ K_EV_USP_sym
    Encryptor enc_m2_ev_reg (.data_in({hash_aj_ev, USP_ID}), .key(USP_SYM_KEY_EV), .data_out(enc_m2_ev_reg_out));

    // CS-USP Registration related crypto
    Decryptor dec_m1_cs_reg (.data_in(cs_msg_in[63:0]), .key(USP_SYM_KEY_CS), .data_out(dec_m1_cs_reg_out));
    // h(ID_k || CH_k || RS_k || ID_j || Pub_j) -> ID_k (dec_m1_cs_reg_out[63:48]), CH_k (dec_m1_cs_reg_out[47:32]), RS_k (dec_m1_cs_reg_out[31:16])
    HashFunction hf_aj_cs (.data_in({dec_m1_cs_reg_out[63:48], dec_m1_cs_reg_out[47:32], dec_m1_cs_reg_out[31:16], USP_ID, USP_SYM_KEY_CS}), .hash_out(hash_aj_cs));
    // E(ID_j || A_j) ^ K_CS_USP_sym
    Encryptor enc_m2_cs_reg (.data_in({USP_ID, hash_aj_cs}), .key(USP_SYM_KEY_CS), .data_out(enc_m2_cs_reg_out));

    // Main FSM logic for USP
    always @(posedge clk or posedge reset) begin
        if (reset) begin // Asynchronous reset
            state <= USP_IDLE;
            usp_msg_out <= 0;
            usp_ack_m2 <= 0;
            reg_ack_ev_usp <= 0;
            reg_ack_cs_usp <= 0;
            registered_ev_id <= 0;
            registered_aj_cs <= 0;
        end else begin
            case (state)
                USP_IDLE: begin
                    // Wait for a registration request from EV or CS
                    if (ev_send_to_usp) state <= USP_EV_REG_WAIT_M1; // EV wants to register
                    else if (cs_send_to_usp) state <= USP_CS_REG_WAIT_M1; // CS wants to register
                end

                // ===================== PHASE 1: EV -> USP Registration (Table 1) =====================
                USP_EV_REG_WAIT_M1: begin
                    if (ev_send_to_usp) begin // M1 received from EV (ev_msg_in)
                        t1_ev_reg <= ev_msg_in[127:64]; // Extract T1 from M1
                        t2_usp_reg <= current_timestamp_usp; // USP's current timestamp for T2
                        // Check |TS2 - TS1| < Delta_t (TS2 is USP's current, TS1 is EV's sent)
                        if ( (t2_usp_reg > t1_ev_reg && (t2_usp_reg - t1_ev_reg) < 64'd1000) ||
                             (t1_ev_reg > t2_usp_reg && (t1_ev_reg - t2_usp_reg) < 64'd1000) ) begin // Delta_t = 1000ns
                            // Decrypt M1 (dec_m1_ev_reg_out)
                            // Compute A_j = h(ID_i || CH_i || RS_i || ID_j || Pub_j) (hash_aj_ev)
                            registered_ev_id <= dec_m1_ev_reg_out[63:48]; // Store ID_i for future reference
                            state <= USP_EV_REG_SEND_M2; // Move to send M2
                        end else begin
                            state <= USP_IDLE; // Timestamp check failed, go back to IDLE
                        end
                    end
                end
                USP_EV_REG_SEND_M2: begin
                    // M2 = E(A_j || ID_j) ^ K_EV_USP_sym || T2
                    usp_msg_out <= {enc_m2_ev_reg_out, t2_usp_reg};
                    usp_ack_m2 <= 1; // Assert ACK signal for M2 sent
                    reg_ack_ev_usp <= 1; // Signal EV registration acknowledged
                    state <= USP_IDLE; // Return to IDLE after sending M2
                end

                // ===================== PHASE 2: CS -> USP Registration (Table 2) =====================
                USP_CS_REG_WAIT_M1: begin
                    if (cs_send_to_usp) begin // M1 received from CS (cs_msg_in)
                        t1_cs_reg <= cs_msg_in[127:64]; // Extract T1 from M1
                        t2_usp_cs_reg <= current_timestamp_usp; // USP's current timestamp for T2
                        // Check |TS2 - TS1| < Delta_t
                        if ( (t2_usp_cs_reg > t1_cs_reg && (t2_usp_cs_reg - t1_cs_reg) < 64'd1000) ||
                             (t1_cs_reg > t2_usp_cs_reg && (t1_cs_reg - t2_usp_cs_reg) < 64'd1000) ) begin // Delta_t = 1000ns
                            // Decrypt M1 (dec_m1_cs_reg_out)
                            // Compute A_j = h(ID_k || CH_k || RS_k || ID_j || Pub_j) (hash_aj_cs)
                            registered_aj_cs <= hash_aj_cs; // Store A_j for this CS
                            state <= USP_CS_REG_SEND_M2; // Move to send M2
                        end else begin
                            state <= USP_IDLE; // Timestamp check failed
                        end
                    end
                end
                USP_CS_REG_SEND_M2: begin
                    // M2 = E(ID_j || A_j) ^ K_CS_USP_sym || T2
                    usp_msg_out <= {enc_m2_cs_reg_out, t2_usp_cs_reg};
                    usp_ack_m2 <= 1; // Assert ACK signal for M2 sent
                    reg_ack_cs_usp <= 1; // Signal CS registration acknowledged
                    state <= USP_IDLE; // Return to IDLE after sending M2
                end
            endcase
        end
    end
endmodule

// ============================================================================
// SECTION: CS Module (Charging Station)
// Handles its own registration with USP and mutual authentication with EV.
// ============================================================================
module CS(
    input clk, input reset,
    // External interfaces (to USP and EV)
    output reg [127:0] cs_msg_out,      // M1/M2/M4 sent from CS (includes timestamp)
    output reg cs_send_to_usp,          // Control signal: CS sends M1 for registration to USP
    output reg cs_send_to_ev,           // Control signal: CS sends M2/M4 for authentication to EV
    input [127:0] usp_msg_in,            // M2 received from USP
    input [127:0] ev_msg_in,             // M1/M3 received from EV
    input usp_ack_m2_cs,                // USP acknowledged M2 to CS
    input ev_ack_m1_m3,                 // EV acknowledged M1/M3 to CS
    // Internal status outputs (for LEDs/top-level monitoring)
    output reg reg_ack_cs_cs,            // CS acknowledges its own registration completion
    output reg [3:0] state              // Expose FSM state for testbench observation
);

    localparam [15:0] CS_ID = 16'h0C51; // CS's ID (ID_k)
    reg [63:0] CS_SYM_KEY_USP = 64'hCAFE_BABE_BEEF_DEAD; // Pre-shared symmetric key with USP
    reg [63:0] CS_SYM_KEY_EV = 64'hCAFE_BABE_DEAD_BEEF; // Pre-shared symmetric key with EV
    localparam [63:0] TOKEN_VAL = 64'hFEED_FACE_BEEF_CAFE; // Defined TOKEN_VAL

    // Finite State Machine (FSM) for CS's protocol execution
    localparam CS_IDLE             = 4'b0000,          // Initial state, waiting for trigger
               // CS-USP Registration States (Table 2)
               CS_REG_INIT         = 4'b0001,          // Initialize registration parameters
               CS_REG_SEND_M1      = 4'b0010,          // Send M1 to USP
               CS_REG_WAIT_M2      = 4'b0011,          // Wait for M2 from USP
               CS_REG_DONE         = 4'b0100,          // CS-USP registration complete

               // EV-CS Authentication States (Table 2)
               CS_AUTH_INIT        = 4'b0101,          // Initialize authentication (wait for EV's M1)
               CS_AUTH_WAIT_M1     = 4'b0110,          // Wait for M1 from EV
               CS_AUTH_SEND_M2     = 4'b0111,          // Send M2 to EV
               CS_AUTH_WAIT_M3     = 4'b1000,          // Wait for M3 from EV
               CS_AUTH_SEND_M4     = 4'b1001,          // Send M4 to EV
               CS_AUTH_DONE        = 4'b1010;          // CS-EV authentication complete

    // Linear Feedback Shift Registers (LFSRs) for Nonce and Timestamp generation
    reg [63:0] nonce_lfsr_cs;     // For CH_k, CH_A, N2, N4, seed
    reg [63:0] timestamp_lfsr_cs; // For T1, T2, T3, T4 and local time checks
    wire lfsr_feedback_nonce_cs = nonce_lfsr_cs[63] ^ nonce_lfsr_cs[58] ^ nonce_lfsr_cs[48] ^ nonce_lfsr_cs[38];
    wire lfsr_feedback_ts_cs    = timestamp_lfsr_cs[63] ^ timestamp_lfsr_cs[55] ^ timestamp_lfsr_cs[45] ^ timestamp_lfsr_cs[35];

    // LFSR update logic
    always @(posedge clk or posedge reset) begin
        if (reset) begin
            nonce_lfsr_cs <= 64'hFEDC_BA98_7654_3210;
            timestamp_lfsr_cs <= 64'h9876_5432_10FE_DCBA;
        end else begin
            nonce_lfsr_cs <= {nonce_lfsr_cs[62:0], lfsr_feedback_nonce_cs};
            timestamp_lfsr_cs <= {timestamp_lfsr_cs[62:0], lfsr_feedback_ts_cs};
        end
    end

    // Internal registers to hold protocol-specific values
    reg [63:0] ch_k, rs_k;          // For CS registration (CH_k, RS_k = PUF(CH_k))
    reg [63:0] ch_a, seed;          // For CS authentication (CH_A, seed)
    reg [63:0] n2, n4;              // Nonces for authentication
    reg [63:0] t1_cs, t2_cs, t3_cs, t4_cs; // Timestamps for freshness checks
    reg [63:0] ka_cs;               // K_a = PUF(seed)
    reg [63:0] tk_cs;               // T_K token (placeholder for blockchain interaction)

    // CS's simplified database (stores A_j from USP after registration)
    reg [63:0] registered_aj_usp;

    // Wires for connecting instances of cryptographic modules
    wire [63:0] puf_rs_k_cs_wire;   // Output of PUF for RS_k (registration)
    wire [63:0] enc_m1_cs_reg_out;  // Encrypted M1 for USP registration
    wire [63:0] dec_m2_cs_reg_out;  // Decrypted M2 from USP registration

    wire [63:0] dec_m1_auth_out;    // Decrypted M1 from EV authentication
    wire [63:0] puf_ka_cs_wire;     // Output of PUF for K_a (authentication)
    wire [63:0] enc_m2_auth_out;    // Encrypted M2 for EV authentication
    wire [63:0] dec_m3_auth_out;    // Decrypted M3 from EV authentication
    wire [63:0] hash_rs_k_cs;       // Output of HashFunction for H(PUF(seed)) on CS side
    wire [63:0] enc_m4_auth_out;    // Encrypted M4 for EV authentication

    // Instantiate cryptographic modules for CS's operations
    // CS-USP Registration related crypto
    PUF puf_reg_cs (.challenge(ch_k), .response(puf_rs_k_cs_wire)); // RS_k = PUF(CH_k)
    // M1 = E(ID_k || CH_k || RS_k) ^ K_CS_USP_sym
    Encryptor enc_m1_cs_reg (.data_in({CS_ID, ch_k, rs_k}), .key(CS_SYM_KEY_USP), .data_out(enc_m1_cs_reg_out));
    Decryptor dec_m2_cs_reg (.data_in(usp_msg_in[63:0]), .key(CS_SYM_KEY_CS), .data_out(dec_m2_cs_reg_out));

    // EV-CS Authentication related crypto
    Decryptor dec_m1_auth (.data_in(ev_msg_in[63:0]), .key(CS_SYM_KEY_EV), .data_out(dec_m1_auth_out));
    PUF puf_auth_ka_cs (.challenge(seed), .response(puf_ka_cs_wire)); // K_a = PUF(seed)
    // M2 = E(ID_k || CH_A || N2 || seed) ^ K_EV_CS_sym
    Encryptor enc_m2_auth (.data_in({CS_ID, ch_a, n2, seed}), .key(CS_SYM_KEY_EV), .data_out(enc_m2_auth_out));
    Decryptor dec_m3_auth (.data_in(ev_msg_in[63:0]), .key(CS_SYM_KEY_EV), .data_out(dec_m3_auth_out));
    HashFunction hf_rs_k_cs (.data_in({puf_ka_cs_wire, 64'h0}), .hash_out(hash_rs_k_cs)); // H(PUF(seed)) (added 64'h0 to match 128-bit input)
    // M4 = E(ID_k || CH_k || N4 || RS_k || T_K || K_a) ^ K_EV_CS_sym
    Encryptor enc_m4_auth (.data_in({CS_ID, ch_k, n4, hash_rs_k_cs, tk_cs, ka_cs}), .key(CS_SYM_KEY_EV), .data_out(enc_m4_auth_out));

    // Main FSM logic for CS
    always @(posedge clk or posedge reset) begin
        if (reset) begin // Asynchronous reset
            state <= CS_IDLE;
            cs_msg_out <= 0;
            cs_send_to_usp <= 0;
            cs_send_to_ev <= 0;
            reg_ack_cs_cs <= 0;
            registered_aj_usp <= 0;
            t1_cs <= 0; t2_cs <= 0; t3_cs <= 0; t4_cs <= 0; // Clear timestamps
            ch_k <= 0; rs_k <= 0; ch_a <= 0; seed <= 0; n2 <= 0; n4 <= 0; ka_cs <= 0; tk_cs <= 0; // Clear internal protocol values
        end else begin
            case (state)
                CS_IDLE: begin
                    // This state is managed by the top-level module (EV_USP_CS_FPGA)
                    // It will transition CS to CS_REG_INIT or CS_AUTH_INIT
                end

                // ===================== PHASE 2: CS -> USP Registration (Table 2) =====================
                CS_REG_INIT: begin
                    ch_k <= nonce_lfsr_cs; // Pick CH_k (random challenge for PUF)
                    rs_k <= puf_rs_k_cs_wire; // Compute RS_k = PUF(CH_k)
                    t1_cs <= timestamp_lfsr_cs; // Pick T1 (current timestamp)
                    state <= CS_REG_SEND_M1; // Move to send M1
                end
                CS_REG_SEND_M1: begin
                    // M1 = E(ID_k || CH_k || RS_k) ^ K_CS_USP_sym || T1
                    cs_msg_out <= {enc_m1_cs_reg_out, t1_cs};
                    cs_send_to_usp <= 1; // Assert send signal to USP
                    state <= CS_REG_WAIT_M2; // Wait for M2 from USP
                end
                CS_REG_WAIT_M2: begin
                    cs_send_to_usp <= 0; // De-assert send signal
                    if (usp_ack_m2_cs) begin // Check if USP has sent M2 and acknowledged
                        // M2 received from USP (usp_msg_in)
                        t2_cs <= usp_msg_in[127:64]; // Extract T2 from M2 (assuming M2 is E(ID_j, A_j) || T2)
                        // Check |TS3 - TS2| < Delta_t (TS3 is current timestamp_lfsr_cs, TS2 is received t2_cs)
                        if ( (timestamp_lfsr_cs > t2_cs && (timestamp_lfsr_cs - t2_cs) < 64'd1000) ||
                             (t2_cs > timestamp_lfsr_cs && (t2_cs - timestamp_lfsr_cs) < 64'd1000) ) begin // Delta_t = 1000ns
                            // Decrypt M2 (dec_m2_cs_reg_out contains ID_j || A_j)
                            registered_aj_usp <= dec_m2_cs_reg_out[31:0]; // Store A_j for this CS
                            reg_ack_cs_cs <= 1; // CS acknowledges its own registration
                            state <= CS_REG_DONE; // Registration complete
                        end else begin
                            reg_ack_cs_cs <= 0; // Registration failed due to timestamp
                            state <= CS_IDLE;
                        end
                    end
                end
                CS_REG_DONE: begin
                    // Hold in this state until triggered by top-level module for authentication
                end

                // ===================== PHASE 3: EV -> CS Authentication (Table 2) =====================
                CS_AUTH_INIT: begin
                    // Wait for M1 from EV (triggered by top-level module)
                    state <= CS_AUTH_WAIT_M1;
                end
                CS_AUTH_WAIT_M1: begin
                    if (ev_ack_m1_m3) begin // Check if EV has sent M1 and acknowledged
                        // M1 received from EV (ev_msg_in)
                        t1_cs <= ev_msg_in[127:64]; // Extract T1 from M1
                        t2_cs <= timestamp_lfsr_cs; // Current timestamp for T2
                        // Check |TS2 - TS1| < Delta_t (TS2 is current t2_cs, TS1 is received t1_cs)
                        if ( (t2_cs > t1_cs && (t2_cs - t1_cs) < 64'd1000) ||
                             (t1_cs > t2_cs && (t1_cs - t2_cs) < 64'd1000) ) begin // Delta_t = 1000ns
                            // Decrypt M1 (dec_m1_auth_out contains PSIDEV || N1)
                            ch_a <= nonce_lfsr_cs; // Pick CH_A (random challenge)
                            seed <= nonce_lfsr_cs + 64'd1; // Pick seed (simple increment for simulation)
                            ka_cs <= puf_ka_cs_wire; // Compute K_a = PUF(seed)
                            n2 <= nonce_lfsr_cs + 64'd2; // Pick N2 (random nonce)
                            state <= CS_AUTH_SEND_M2; // Move to send M2
                        end else begin
                            state <= CS_IDLE; // Authentication failed due to timestamp
                        end
                    end
                end
                CS_AUTH_SEND_M2: begin
                    // M2 = E(ID_k || CH_A || N2 || seed) ^ K_EV_CS_sym || T2
                    cs_msg_out <= {enc_m2_auth_out, t2_cs};
                    cs_send_to_ev <= 1; // Assert send signal to EV
                    state <= CS_AUTH_WAIT_M3; // Wait for M3 from EV
                end
                CS_AUTH_WAIT_M3: begin
                    cs_send_to_ev <= 0; // De-assert send signal
                    if (ev_ack_m1_m3) begin // Check if EV has sent M3 and acknowledged
                        // M3 received from EV (ev_msg_in)
                        t3_cs <= ev_msg_in[127:64]; // Extract T3 from M3
                        t4_cs <= timestamp_lfsr_cs; // Current timestamp for T4
                        // Check |TS4 - TS3| < Delta_t
                        if ( (t4_cs > t3_cs && (t4_cs - t3_cs) < 64'd1000) ||
                             (t3_cs > t4_cs && (t3_cs - t4_cs) < 64'd1000) ) begin // Delta_t = 1000ns
                            // Decrypt M3 (dec_m3_auth_out contains PSIDEV || CH_k || RS || RS_k || K_a)
                            // Generate token T_K (using a simple value for simulation)
                            tk_cs <= TOKEN_VAL; // Placeholder for T_K (no blockchain interaction)
                            // Compute RS_k = H(PUF(seed)) (hash_rs_k_cs)
                            n4 <= nonce_lfsr_cs + 64'd3; // Pick N4 (random nonce)
                            state <= CS_AUTH_SEND_M4; // Move to send M4
                        end else begin
                            state <= CS_IDLE; // Authentication failed due to timestamp
                        end
                    end
                end
                CS_AUTH_SEND_M4: begin
                    // M4 = E(ID_k || CH_k || N4 || RS_k || T_K || K_a) ^ K_EV_CS_sym || T4
                    // Note: CH_k is not explicitly sent by EV, assuming it's derived or a fixed value here.
                    cs_msg_out <= {enc_m4_auth_out, t4_cs};
                    cs_send_to_ev <= 1; // Assert send signal to EV
                    state <= CS_AUTH_DONE; // Authentication complete
                end
                CS_AUTH_DONE: begin
                    cs_send_to_ev <= 0; // De-assert send signal
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
    output wire [3:0] ev_state_out, // Expose EV FSM state
    output wire [2:0] usp_state_out, // Expose USP FSM state
    output wire [3:0] cs_state_out // Expose CS FSM state
);
    // Wires for inter-module communication signals (messages and control)
    // EV-USP communication
    wire [127:0] ev_msg_to_usp;     // M1 from EV to USP (includes timestamp)
    wire [127:0] usp_msg_to_ev;     // M2 from USP to EV (includes timestamp)
    wire ev_send_to_usp_sig;        // EV's signal to send to USP
    wire usp_ack_m2_sig;            // USP's acknowledgment for M2 sent to EV/CS

    // CS-USP communication
    wire [127:0] cs_msg_to_usp;     // M1 from CS to USP (includes timestamp)
    wire [127:0] usp_msg_to_cs;     // M2 from USP to CS (includes timestamp)
    wire cs_send_to_usp_sig;        // CS's signal to send to USP
    wire usp_ack_m2_cs_sig;         // USP's acknowledgment for M2 sent to CS (same as usp_ack_m2_sig)

    // EV-CS communication
    wire [127:0] ev_msg_to_cs;      // M1/M3 from EV to CS (includes timestamp)
    wire [127:0] cs_msg_to_ev;      // M2/M4 from CS to EV (includes timestamp)
    wire ev_send_to_cs_sig;         // EV's signal to send to CS
    wire cs_send_to_ev_sig;         // CS's signal to send to EV

    // Status signals from sub-modules for LED mapping
    wire auth_pass_ev_usp_sig;      // EV-USP registration/authentication success
    wire final_ack_ev_cs_sig;       // EV-CS mutual authentication success
    wire reg_ack_ev_usp_sig;        // EV registration acknowledged by USP
    wire reg_ack_cs_usp_sig;        // CS registration acknowledged by USP
    wire reg_ack_cs_cs_sig;         // CS acknowledges its own registration completion

    // Internal FSM states from sub-modules
    wire [3:0] ev_state_internal;
    wire [2:0] usp_state_internal;
    wire [3:0] cs_state_internal;


    // Instantiate the EV, USP, and CS modules
    EV ev_inst (
        .clk(clk), .reset(reset),
        .ev_msg_out(ev_msg_to_usp[63:0]),         // EV M1 data to USP (only data part, timestamp appended in EV)
        .ev_send_to_usp(ev_send_to_usp_sig),
        .ev_send_to_cs(ev_send_to_cs_sig),  // EV M1/M3 data to CS (only data part, timestamp appended in EV)
        .usp_msg_in(usp_msg_to_ev[63:0]),         // USP M2 data to EV
        .cs_msg_in(cs_msg_to_ev[63:0]),           // CS M2/M4 data to EV
        .usp_ack_m2(usp_ack_m2_sig),        // USP's M2 ACK to EV
        .cs_ack_m2_m4(cs_send_to_ev_sig),   // CS's send M2/M4 signal acts as ACK for EV
        .auth_pass_ev_usp(auth_pass_ev_usp_sig),
        .final_ack_ev_cs(final_ack_ev_cs_sig),
        .state(ev_state_internal) // Connect EV's internal state
    );

    USP usp_inst (
        .clk(clk), .reset(reset),
        .ev_msg_in(ev_msg_to_usp),          // EV M1 to USP (full 128-bit message)
        .ev_send_to_usp(ev_send_to_usp_sig),
        .usp_msg_out(usp_msg_to_ev),        // USP M2 to EV (full 128-bit message)
        .usp_ack_m2(usp_ack_m2_sig),
        .cs_msg_in(cs_msg_to_usp),          // CS M1 to USP (full 128-bit message)
        .cs_send_to_usp(cs_send_to_usp_sig),
        .reg_ack_ev_usp(reg_ack_ev_usp_sig),
        .reg_ack_cs_usp(reg_ack_cs_usp_sig),
        .state(usp_state_internal) // Connect USP's internal state
    );

    CS cs_inst (
        .clk(clk), .reset(reset),
        .cs_msg_out(cs_msg_to_usp),         // CS M1 to USP (full 128-bit message)
        .cs_send_to_usp(cs_send_to_usp_sig),
        .cs_send_to_ev(cs_send_to_ev_sig),  // CS M2/M4 to EV (full 128-bit message)
        .usp_msg_in(usp_msg_to_cs),         // USP M2 to CS (full 128-bit message)
        .ev_msg_in(ev_msg_to_ev),           // EV M1/M3 to CS (full 128-bit message)
        .usp_ack_m2_cs(usp_ack_m2_sig),     // USP's M2 ACK to CS
        .ev_ack_m1_m3(ev_send_to_cs_sig),   // EV's send M1/M3 signal acts as ACK for CS
        .reg_ack_cs_cs(reg_ack_cs_cs_sig),
        .state(cs_state_internal) // Connect CS's internal state
    );

    // Expose internal states to top-level outputs for testbench
    assign ev_state_out = ev_state_internal;
    assign usp_state_out = usp_state_internal;
    assign cs_state_out = cs_state_internal;

    // Top-level FSM to sequence the three main phases of the protocol for simulation.
    // This ensures that registration happens before authentication.
    localparam TOP_IDLE        = 2'b00, // Initial state
               TOP_EV_REG      = 2'b01, // Phase 1: EV Registration with USP
               TOP_CS_REG      = 2'b10, // Phase 2: CS Registration with USP
               TOP_EV_CS_AUTH  = 2'b11; // Phase 3: EV Authentication with CS

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            top_state <= TOP_IDLE;
            // Ensure sub-modules are also reset to their IDLE states
            // These assignments directly set the state registers of the instances.
            // This is a common practice in top-level FSMs that control sub-module FSMs
            // by directly manipulating their exposed state outputs (which are reg type).
            // This is acceptable for simulation and synthesis as long as the sub-module
            // state is declared as 'output reg' and not 'output wire'.
            ev_inst.state <= 4'b0000; // EV_IDLE
            usp_inst.state <= 3'b000; // USP_IDLE
            cs_inst.state <= 4'b0000; // CS_IDLE
        end else begin
            case (top_state)
                TOP_IDLE: begin
                    // After reset, start the first phase (EV Registration)
                    top_state <= TOP_EV_REG;
                    ev_inst.state <= 4'b0001; // EV_REG_INIT
                end
                TOP_EV_REG: begin
                    // Wait for EV-USP registration to complete
                    if (ev_state_internal == 4'b0100) begin // Check for EV_REG_DONE
                        top_state <= TOP_CS_REG;
                        cs_inst.state <= 4'b0001; // CS_REG_INIT
                    end
                end
                TOP_CS_REG: begin
                    // Wait for CS-USP registration to complete
                    if (cs_state_internal == 4'b0100) begin // Check for CS_REG_DONE
                        top_state <= TOP_EV_CS_AUTH;
                        ev_inst.state <= 4'b0101; // EV_AUTH_INIT
                        cs_inst.state <= 4'b0101; // CS_AUTH_INIT
                    end
                end
                TOP_EV_CS_AUTH: begin
                    // Wait for EV-CS authentication to complete
                    if (ev_state_internal == 4'b1010 && cs_state_internal == 4'b1010) begin // Check for EV_AUTH_DONE and CS_AUTH_DONE
                        // All phases complete, return to IDLE or hold
                        top_state <= TOP_IDLE; // For continuous simulation, could loop or stop
                    end
                end
            endcase
        end
    end

    // Map internal status signals to the 4-bit LED output
    // leds[3]: Final EV-CS Authentication Success (final_ack_ev_cs_sig)
    // leds[2]: EV-USP Registration/Authentication Success (auth_pass_ev_usp_sig)
    // leds[1]: CS-USP Registration Acknowledged by USP (reg_ack_cs_usp_sig)
    // leds[0]: EV-USP Registration Acknowledged by EV (reg_ack_ev_usp_sig)
    assign leds = {final_ack_ev_cs_sig, auth_pass_ev_usp_sig, reg_ack_cs_usp_sig, reg_ack_ev_usp_sig};

endmodule
