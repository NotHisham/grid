// =================================================================================
// Verilog Code for an Electric Vehicle (EV) Charging System
//
// This code is split into three modules:
// 1. EV Registration with USP
// 2. CS Registration with USP
// 3. EV-CS Authentication
// =================================================================================


// =================================================================================
// MODULE 1: EV Registration with the Utility Service Provider (USP)
// Follows "Table 1: Registration of EV with USP".
// =================================================================================
module EV_USP_Registration (
    input clk,             // Clock signal
    input rst,             // Reset signal
    input [63:0] ev_id_i,  // EV's unique Identity (IDi)
    input [63:0] ev_ch_i,  // EV's secret Challenge (CHi)
    input [63:0] usp_pub_key_j, // USP's Public Key
    output reg [191:0] M1,   // Message 1 (EV to USP)
    output reg [127:0] M2,   // Message 2 (USP to EV)
    output reg registration_complete // Flag for completion
);

    reg [63:0] rs_i;
    reg [63:0] psidev_i;
    reg [63:0] a_j;
    reg [63:0] usp_id_j;
    reg [63:0] decrypted_aj;
    reg [63:0] decrypted_idj;

    // PUF: Linear Feedback Shift Register (LFSR) based
    function [63:0] puf (input [63:0] challenge);
        reg [63:0] lfsr_reg;
        integer i;
        begin
            lfsr_reg = challenge;
            for (i = 0; i < 64; i = i + 1) begin
                lfsr_reg = {lfsr_reg[62:0], lfsr_reg[63] ^ lfsr_reg[62] ^ lfsr_reg[60] ^ lfsr_reg[59]};
            end
            puf = lfsr_reg;
        end
    endfunction

    // Hash function: Multi-round permutation for 256-bit input
    function [63:0] hash (input [255:0] data);
        reg [63:0] state;
        reg [63:0] round_key;
        integer i;
        reg [63:0] data_chunk;
        begin
            state = 64'hA5A5A5A5A5A5A5A5;
            for (i = 0; i < 4; i = i + 1) begin
                case(i)
                    0: data_chunk = data[63:0];
                    1: data_chunk = data[127:64];
                    2: data_chunk = data[191:128];
                    3: data_chunk = data[255:192];
                    default: data_chunk = 64'h0;
                endcase
                state = state ^ data_chunk;
                round_key = 64'hC3C3C3C3C3C3C3C3 >> (i * 8);
                state = (state <<< 3) ^ (state >> 5) ^ round_key;
            end
            hash = state;
        end
    endfunction
    
    // Encryption/Decryption functions (XOR-based)
    function [191:0] encrypt_m1 (input [191:0] plaintext, input [63:0] key);
        encrypt_m1 = plaintext ^ {3{key}};
    endfunction
    function [127:0] encrypt_m2 (input [127:0] plaintext, input [63:0] key);
        encrypt_m2 = plaintext ^ {2{key}};
    endfunction

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            M1 <= 0; M2 <= 0; registration_complete <= 0;
            rs_i <= 0; psidev_i <= 0; a_j <= 0;
        end else begin
            // EV SIDE: Step 1 - Preparation
            rs_i <= puf(ev_ch_i); // RSi = PUF(CHi)
            psidev_i <= hash({ev_id_i, rs_i, 128'd0}); // PSIDEVi = h(IDi || RSi)
            M1 <= encrypt_m1({psidev_i, ev_ch_i, rs_i}, usp_pub_key_j); // M1 = E(PSIDEVi || CHi || RSi, Pubj)

            // USP SIDE: Step 2 - Verification and Response
            usp_id_j <= 64'hABCDEF9876543210; // USP ID
            a_j <= hash({ev_id_i, ev_ch_i, rs_i, usp_id_j}); // Aj = H(IDi || CHi || RSi || IDj)
            M2 <= encrypt_m2({usp_id_j, a_j}, ev_id_i); // M2 = E(IDj || Aj, IDi)

            // EV SIDE: Step 3 - Finalization
            {decrypted_idj, decrypted_aj} <= encrypt_m2(M2, ev_id_i); // Decrypt M2
            registration_complete <= 1;
        end
    end
endmodule


// =================================================================================
// MODULE 2: CS Registration with the Utility Service Provider (USP)
// =================================================================================
module CS_USP_Registration (
    input clk,
    input rst,
    input [63:0] cs_id_k,
    input [63:0] cs_ch_k,
    input [63:0] cs_rs_k,
    input [63:0] cs_pub_key_k,
    input [63:0] usp_pub_key_j,
    output reg [255:0] M1,
    output reg [127:0] M2,
    output reg registration_complete
);

    reg [63:0] a_j;
    reg [63:0] usp_id_j;
    reg [63:0] decrypted_aj;
    reg [63:0] decrypted_idj;

    // Hash function for 320-bit input
    function [63:0] hash (input [319:0] data);
        reg [63:0] state;
        reg [63:0] round_key;
        integer i;
        reg [63:0] data_chunk;
        begin
            state = 64'hA5A5A5A5A5A5A5A5;
            for (i = 0; i < 5; i = i + 1) begin
                case(i)
                    0: data_chunk = data[63:0];
                    1: data_chunk = data[127:64];
                    2: data_chunk = data[191:128];
                    3: data_chunk = data[255:192];
                    4: data_chunk = data[319:256];
                    default: data_chunk = 64'h0;
                endcase
                state = state ^ data_chunk;
                round_key = 64'hC3C3C3C3C3C3C3C3 >> (i * 7);
                state = (state <<< 3) ^ (state >> 5) ^ round_key;
            end
            hash = state;
        end
    endfunction

    // Encryption/Decryption functions
    function [255:0] encrypt_m1 (input [255:0] plaintext, input [63:0] key);
        encrypt_m1 = plaintext ^ {4{key}};
    endfunction
    function [127:0] encrypt_m2 (input [127:0] plaintext, input [63:0] key);
        encrypt_m2 = plaintext ^ {2{key}};
    endfunction

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            M1 <= 0; M2 <= 0; registration_complete <= 0; a_j <= 0; usp_id_j <= 0;
        end else begin
            M1 <= encrypt_m1({cs_id_k, cs_ch_k, cs_rs_k, cs_pub_key_k}, usp_pub_key_j);

            usp_id_j <= 64'hFEDCBA0987654321;
            a_j <= hash({cs_id_k, cs_ch_k, cs_rs_k, usp_id_j, cs_pub_key_k});
            M2 <= encrypt_m2({usp_id_j, a_j}, cs_pub_key_k);

            {decrypted_idj, decrypted_aj} <= encrypt_m2(M2, cs_pub_key_k);
            registration_complete <= 1;
        end
    end
endmodule

// =================================================================================
// MODULE 3: EV-CS Authentication
// =================================================================================
module EV_CS_Authentication (
    input clk,
    input rst,
    input [63:0] ev_psidev_i,
    input [63:0] ev_pub_key,
    input [63:0] cs_pub_key,
    input [63:0] ev_retrieved_rs_i,
    output reg mutual_authentication_established
);

    reg [63:0] ev_n1, cs_n2, cs_n4;
    reg [191:0] m1; reg [255:0] m2; reg [319:0] m3; reg [319:0] m4;
    reg [63:0] cs_ch_k, cs_seed, cs_k_k, cs_id_k, token_tk_k, rs_k_prime, k_sk;
    wire [63:0] ev_ch_k, ev_k_a;
    reg [63:0] ev_k_i;
    reg ev_cs_verified;

    // PUF model
    function [63:0] puf (input [63:0] challenge);
        reg [63:0] lfsr_reg; integer i;
        begin
            lfsr_reg = challenge;
            for (i = 0; i < 64; i = i + 1) begin
                lfsr_reg = {lfsr_reg[62:0], lfsr_reg[63] ^ lfsr_reg[62] ^ lfsr_reg[60] ^ lfsr_reg[59]};
            end
            puf = lfsr_reg;
        end
    endfunction

    // Hash model for 192-bit input
    function [63:0] hash (input [191:0] data);
        reg [63:0] state; reg [63:0] round_key; integer i;
        reg [63:0] data_chunk;
        begin
            state = 64'hA5A5A5A5A5A5A5A5;
            for (i = 0; i < 3; i = i + 1) begin
                case(i)
                    0: data_chunk = data[63:0];
                    1: data_chunk = data[127:64];
                    2: data_chunk = data[191:128];
                    default: data_chunk = 64'h0;
                endcase
                state = state ^ data_chunk;
                round_key = 64'hC3C3C3C3C3C3C3C3 >> (i * 9);
                state = (state <<< 3) ^ (state >> 5) ^ round_key;
            end
            hash = state;
        end
    endfunction

    // Encryption model
    function [319:0] encrypt (input [319:0] plaintext, input [63:0] key);
        encrypt = plaintext ^ {5{key}};
    endfunction

    // Continuous assignments for derived signals
    wire [255:0] temp_m2_xor_ev_pub_key;
    assign temp_m2_xor_ev_pub_key = m2 ^ {4{ev_pub_key}};
    assign ev_ch_k = temp_m2_xor_ev_pub_key[191:128];

    wire [319:0] temp_m4_xor_ev_k_i;
    assign temp_m4_xor_ev_k_i = m4 ^ {5{ev_k_i}};
    assign ev_k_a = temp_m4_xor_ev_k_i[127:64];


    always @(posedge clk or posedge rst) begin
        if (rst) begin
            mutual_authentication_established <= 0;
            ev_k_i <= 0;
            ev_cs_verified <= 0;
        end else begin
            // STEP 1: EV sends M1 to CS
            ev_n1 <= 64'h1111_1111_1111_1111;
            m1 <= {ev_psidev_i, ev_n1, ev_pub_key} ^ {3{cs_pub_key}};

            // STEP 2: CS receives M1 and sends back M2
            cs_ch_k <= 64'hAAAAAAAAAAAAAAAA;
            cs_seed <= 64'hBBBBBBBBBBBBBBBB;
            cs_k_k <= puf(cs_seed);
            cs_n2 <= 64'h2222_2222_2222_2222;
            cs_id_k <= 64'hDDDDDDDDDDDDDDDD;
            m2 <= {cs_id_k, cs_ch_k, cs_n2, cs_seed} ^ {4{ev_pub_key}};

            ev_k_i <= puf(m2[63:0]); // Corrected: pass 64-bit value to puf
            m3 <= {ev_psidev_i, ev_ch_k, ev_retrieved_rs_i, ev_ch_k, ev_k_i} ^ {5{cs_pub_key}};

            // STEP 4: CS receives M3, authenticates EV, and sends final message M4
            token_tk_k <= hash({ev_psidev_i, ev_retrieved_rs_i, cs_id_k});
            rs_k_prime <= puf(cs_ch_k);
            k_sk <= hash({cs_k_k, 128'd0}); // Pad to fit 192-bit hash input
            cs_n4 <= 64'h4444_4444_4444_4444;
            m4 <= {cs_id_k, cs_ch_k, cs_n4, rs_k_prime, token_tk_k} ^ {5{ev_k_i}};

            if (ev_k_a == puf(ev_ch_k)) begin
                ev_cs_verified <= 1;
            end else begin
                ev_cs_verified <= 0;
            end

            if(ev_cs_verified) begin
                mutual_authentication_established <= 1;
            end else begin
                mutual_authentication_established <= 0;
            end
        end
    end
endmodule
