//------------------------
// Crypto Utility Library
//------------------------
module crypto_utils;

function [63:0] puf(input [63:0] challenge);
    reg [63:0] lfsr_reg; integer i;
    begin
        lfsr_reg = challenge;
        for (i = 0; i < 64; i = i + 1)
            lfsr_reg = {lfsr_reg[62:0], lfsr_reg[63] ^ lfsr_reg[62] ^ lfsr_reg[60] ^ lfsr_reg[59]};
        puf = lfsr_reg;
    end
endfunction

function [63:0] hash192(input [255:0] data);
    reg [63:0] state; reg [63:0] round_key; integer i; reg [63:0] chunk;
    begin
        state = 64'hA5A5A5A5A5A5A5A5;
        for (i = 0; i < 4; i = i + 1) begin
            chunk = data[i*64 +: 64];
            round_key = 64'hC3C3C3C3C3C3C3C3 >> (i * 9);
            state = (state ^ chunk) ^ ((state <<< 3) ^ (state >> 5)) ^ round_key;
        end
        hash192 = state;
    end
endfunction

function [255:0] xor256_k64(input [255:0] msg, input [63:0] key);
    xor256_k64 = msg ^ {4{key}};
endfunction

function [319:0] xor320_k64(input [319:0] msg, input [63:0] key);
    xor320_k64 = msg ^ {5{key}};
endfunction

function [383:0] xor384_k64(input [383:0] msg, input [63:0] key);
    xor384_k64 = msg ^ {6{key}};
endfunction

function [447:0] xor448_k64(input [447:0] msg, input [63:0] key);
    xor448_k64 = msg ^ {7{key}};
endfunction

function [63:0] lfsr_next(input [63:0] current);
    lfsr_next = {current[62:0], current[63] ^ current[62] ^ current[60] ^ current[59]};
endfunction

function [63:0] puf_i(input [63:0] challenge);
    puf_i = puf(challenge);
endfunction

function [63:0] puf_k(input [63:0] challenge);
    puf_k = puf(challenge);
endfunction

endmodule


//------------------------
// EV-USP Registration
//------------------------
module EV_USP_Registration (
    input clk,
    input rst,
    input [63:0] ev_id_i,
    input [63:0] ev_ch_i,
    input [63:0] T1_ev_in,
    input [63:0] ev_pub_key_i,
    input [63:0] common_key,
    input [63:0] usp_id_j,
    input [63:0] usp_pub_key_j,
    output reg [255:0] M1,
    output reg [191:0] M2,
    output reg registration_complete,
    output reg registration_failed
);
    import crypto_utils::*;
    parameter ACCEPTABLE_DELAY = 10;

    reg [63:0] rs_i;
    reg [63:0] psidev_i;
    reg [63:0] TS2, TS3;
    reg [63:0] received_t1;
    reg [63:0] nonce_j;
    reg [63:0] Aj;
    reg [255:0] temp_m1_decrypted;
    reg [191:0] temp_m2;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            M1 <= 0; M2 <= 0; registration_complete <= 0; registration_failed <= 0;
            rs_i <= 0; psidev_i <= 0; TS2 <= 0; TS3 <= 0; received_t1 <= 0;
        end else begin
            rs_i <= puf(ev_ch_i);
            psidev_i <= hash192({ev_id_i, rs_i});
            M1 <= xor256_k64({psidev_i, ev_ch_i, rs_i, ev_pub_key_i}, common_key);
            temp_m1_decrypted = xor256_k64(M1, common_key);
            received_t1 = T1_ev_in;
            TS2 <= T1_ev_in + 4;

            if ((TS2 - received_t1) > ACCEPTABLE_DELAY) begin
                registration_failed <= 1;
                registration_complete <= 0;
            end else begin
                nonce_j <= 64'hCAFEBABECAFEBABE;
                Aj <= hash192({ev_id_i, ev_ch_i, rs_i, usp_id_j, usp_pub_key_j});
                M2 <= xor256_k64({Aj, usp_id_j, usp_pub_key_j}, common_key);
                TS3 <= TS2 + 4;

                if ((TS3 - TS2) > ACCEPTABLE_DELAY) begin
                    registration_failed <= 1;
                    registration_complete <= 0;
                end else begin
                    temp_m2 = xor256_k64(M2, common_key);
                    Aj <= temp_m2[191:128];
                    registration_complete <= 1;
                    registration_failed <= 0;
                end
            end
        end
    end
endmodule



//------------------------
// CS-USP Registration
//------------------------
module CS_USP_Registration (
    input  wire        clk,
    input  wire        rst,
    input  wire [63:0] cs_id_k,
    input  wire [63:0] cs_pub_key_k,
    input  wire [63:0] T1_cs_in,
    input  wire [63:0] usp_id_j,
    input  wire [63:0] usp_pub_key_j,
    input  wire [63:0] prvk,
    output reg  [255:0] M1,
    output reg  [127:0] M2,
    output reg          registration_complete,
    output reg          registration_failed
);
    import crypto_utils::*;
    parameter ACCEPTABLE_DELAY = 10;

    // Internal random number state for nonce/challenge
    reg [63:0] lfsr_state;
    reg [63:0] cs_ch_k;  // generated nonce (challenge)
    reg [63:0] cs_rs_k;
    reg [63:0] TS2, TS3, received_t1;
    reg [63:0] Aj;
    reg [127:0] temp_m2;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            {M1, M2} <= 0;
            {registration_complete, registration_failed} <= 0;
            {TS2, TS3, received_t1, Aj} <= 0;
            lfsr_state <= 64'h1;
        end else begin
            // Generate fresh challenge and response
            lfsr_state <= lfsr_next(lfsr_state);
            cs_ch_k    <= lfsr_state;
            cs_rs_k    <= puf(cs_ch_k);

            //---------------- Build and send M1 ----------------
            M1 <= xor256_k64({cs_id_k, cs_ch_k, cs_rs_k, cs_pub_key_k}, usp_pub_key_j);
            received_t1 <= T1_cs_in;
            TS2 <= T1_cs_in + 4;

            // Freshness check for M1
            if ((TS2 - received_t1) > ACCEPTABLE_DELAY) begin
                registration_failed    <= 1;
                registration_complete  <= 0;
            end else begin
                //---------------- Compute Aj and build M2 --------
                Aj <= hash192({cs_id_k, cs_ch_k, cs_rs_k, usp_id_j, usp_pub_key_j, cs_pub_key_k});
                M2 <= xor256_k64({usp_id_j, Aj}, prvk);
                TS3 <= TS2 + 4;

                // Freshness check for M2
                if ((TS3 - TS2) > ACCEPTABLE_DELAY) begin
                    registration_failed    <= 1;
                    registration_complete  <= 0;
                end else begin
                    temp_m2 = xor256_k64(M2, prvk);
                    Aj      <= temp_m2[63:0];
                    registration_complete  <= 1;
                    registration_failed    <= 0;
                end
            end
        end
    end
endmodule



//------------------------
// EV-CS Authentication
//------------------------
module EV_CS_Authentication #(
    parameter ACCEPTABLE_DELAY = 10
)(
    input  wire        clk,
    input  wire        rst,
    input  wire [63:0] ev_psidev_i,
    input  wire [63:0] ev_rs_i,
    input  wire [63:0] ev_pub_key_i,
    input  wire [63:0] cs_pub_key_k,
    input  wire [63:0] cs_prv_key_k,
    output reg         mutual_auth_ok
);
    import crypto_utils::*;

    // RNG / nonces
    reg [63:0] lfsr, N1, N2, N4;
    // Challenges and seed
    reg [63:0] CH_i, CH_k, seed;
    // Derived keys
    reg [63:0] k_i, k_k, k_ki, k_ik;
    // Messages
    reg [255:0] M1;
    reg [319:0] M2, M2_dec;
    reg [383:0] M3;
    reg [447:0] M4, M4_dec;
    // Timing
    reg [63:0] TS1, TS2, TS3, TS4, TS5;
    // RS values
    reg [63:0] RS_prime_i, RS_k_received;
    // Token
    reg [63:0] TK_i;

    localparam [63:0] CS_ID = 64'hDDDDDDDDDDDDDDDD;
    localparam [63:0] T_VALID = 64'd60; // token validity

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            mutual_auth_ok <= 0;
            lfsr <= 64'h3;
        end else begin
            lfsr <= lfsr_next(lfsr);
            N1   <= lfsr;
            TS1  <= $time;
            M1   <= xor256_k64({ev_psidev_i, N1, ev_pub_key_i}, cs_pub_key_k);

            TS2 = TS1 + 5;
            if ((TS2 - TS1) > ACCEPTABLE_DELAY) begin
                mutual_auth_ok <= 0;
            end else begin
                CH_i <= 64'hAAAAAAAAAAAAAAAA;
                seed <= 64'hBBBBBBBBBBBBBBBB;
                N2   <= lfsr_next(lfsr);
                M2   <= xor320_k64({CS_ID, CH_i, N2, seed}, ev_pub_key_i);

                TS3 = TS2 + 4;
                if ((TS3 - TS2) > ACCEPTABLE_DELAY) begin
                    mutual_auth_ok <= 0;
                end else begin
                    M2_dec    = xor320_k64(M2, ev_pub_key_i);
                    CH_i      <= M2_dec[255:192];
                    seed      <= M2_dec[127:64];
                    RS_prime_i <= puf_i(CH_i);

                    if (RS_prime_i != ev_rs_i) begin
                        mutual_auth_ok <= 0;
                    end else begin
                        CH_k <= lfsr_next(lfsr);
                        k_i  <= puf_i(seed);
                        M3   <= xor384_k64({ev_psidev_i, CH_i, RS_prime_i, CH_k, k_i}, cs_pub_key_k);
                        TS4 = TS3 + 6;
                        if ((TS4 - TS3) > ACCEPTABLE_DELAY) begin
                            mutual_auth_ok <= 0;
                        end else begin
                            k_k   <= puf_k(seed);
                            k_ki  <= hash192(k_i ^ k_k);
                            N4    <= lfsr_next(lfsr);
                            RS_k_received = puf(CH_k);
                            TK_i  <= hash192({ev_psidev_i, T_VALID, RS_prime_i, CS_ID});
                            M4    <= xor448_k64({CS_ID, CH_k, N4, RS_k_received, TK_i, k_k}, k_ki);
                            TS5 = TS4 + 5;
                            M4_dec = xor448_k64(M4, k_ki);
                            RS_k_received = M4_dec[191:128];
                            k_ik = hash192(k_i ^ k_k);

                            if ((TS5 - TS4) <= ACCEPTABLE_DELAY && RS_k_received == RS_prime_i && k_ik == k_ki) begin
                                mutual_auth_ok <= 1;
                            end else begin
                                mutual_auth_ok <= 0;
                            end
                        end
                    end
                end
            end
        end
    end
endmodule
