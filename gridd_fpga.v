//------------------------
// Crypto Utility Library (now functions only, not a separate module)
//------------------------

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

    reg [63:0] lfsr, N1, N2, N4;
    reg [63:0] CH_i, CH_k, seed;
    reg [63:0] k_i, k_k, k_ki, k_ik;
    reg [255:0] M1;
    reg [319:0] M2, M2_dec;
    reg [383:0] M3;
    reg [447:0] M4, M4_dec;
    reg [63:0] TS1, TS2, TS3, TS4, TS5;
    reg [63:0] RS_prime_i, RS_k_received;
    reg [63:0] RS_k_local;
    reg [63:0] TK_i;

    localparam [63:0] CS_ID = 64'hDDDDDDDDDDDDDDDD;
    localparam [63:0] T_VALID = 64'd60;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            mutual_auth_ok <= 0;
            lfsr <= 64'h3;
        end else begin
            lfsr <= lfsr_next(lfsr);
            N1   <= lfsr;
            TS1  <= $time;
            M1   <= xor256_k64({64'd0, ev_psidev_i, N1, ev_pub_key_i}, cs_pub_key_k);

            TS2 = TS1 + 5;
            if ((TS2 - TS1) > ACCEPTABLE_DELAY) begin
                mutual_auth_ok <= 0;
            end else begin
                CH_i <= 64'hAAAAAAAAAAAAAAAA;
                seed <= 64'hBBBBBBBBBBBBBBBB;
                N2   <= lfsr_next(lfsr);
                k_k  <= puf_k(seed);
                M2   <= xor320_k64({CS_ID, CH_i, N2, seed, 64'd0}, ev_pub_key_i);

                TS3 = TS2 + 4;
                if ((TS3 - TS2) > ACCEPTABLE_DELAY) begin
                    mutual_auth_ok <= 0;
                end else begin
                    M2_dec    = xor320_k64(M2, ev_pub_key_i);
                    CH_i      <= M2_dec[255:192];
                    seed      <= M2_dec[127:64];
                    RS_prime_i <= puf_i(CH_i);
                    CH_k <= lfsr_next(lfsr);
                    k_i  <= puf_i(seed);
                    M3   <= xor384_k64({ev_psidev_i, CH_i, RS_prime_i, CH_k, k_i, 64'd0}, cs_pub_key_k);
                    TS4 = TS3 + 6;
                    if ((TS4 - TS3) > ACCEPTABLE_DELAY) begin
                        mutual_auth_ok <= 0;
                    end else begin
                        if (RS_prime_i != ev_rs_i) begin
                            mutual_auth_ok <= 0;
                        end else begin
                            N4    <= lfsr_next(lfsr);
                            TK_i  <= hash192({ev_psidev_i, T_VALID, RS_prime_i, CS_ID});
                            RS_k_local = puf(CH_k);
                            k_ki  <= hash192({192'd0, k_i ^ k_k});
                            M4    <= xor448_k64({CS_ID, CH_k, N4, RS_k_local, TK_i, k_k, 64'd0}, k_ki);
                            TS5 = TS4 + 5;
                            M4_dec = xor448_k64(M4, k_ki);
                            RS_k_received = M4_dec[255:192];
                            k_ik = hash192({192'd0, k_i ^ k_k});

                            if ((TS5 - TS4) <= ACCEPTABLE_DELAY && RS_k_received == RS_k_local && k_ik == k_ki) begin
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
