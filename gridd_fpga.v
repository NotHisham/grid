//############################################################################
//
// Module: Top_Authentication_System_for_ZCU104
// Description: Top-level module integrating registration and authentication
//              for an Electric Vehicle (EV) and Charging Station (CS).
//
//############################################################################
module Top_Authentication_System_for_ZCU104 (
    input  wire clk,
    input  wire rst,
    input  wire start_registration_ev,
    input  wire start_registration_cs,
    input  wire start_authentication,

    output wire ev_reg_status,
    output wire cs_reg_status,
    output wire ev_auth_status,
    output wire cs_auth_status,
    output wire mutual_auth_status,
    output wire auth_process_active
);

    // Parameters
    localparam [63:0] USP_ID_J = 64'hDDDDDDDDDDDDDDDD;
    localparam [63:0] USP_PUB_KEY_J = 64'hF0F0F0F0F0F0F0F0;
    localparam [63:0] COMMON_KEY_USP = 64'h1A2B3C4D5E6F7A8B;
    localparam TIMEOUT_CYCLES = 24'd25_000_000; // ~200ms at 125MHz

    // Wires and Registers for sub-module connections
    wire [63:0] ev_psidev_reg;
    wire [63:0] ev_rs_reg;
    wire [63:0] ev_pub_key_reg;
    wire [63:0] ev_prv_key_reg;
    wire        ev_registration_complete;
    wire        ev_registration_failed;

    wire [63:0] cs_id_reg;
    wire [63:0] cs_pub_key_reg;
    wire [63:0] cs_prv_key_reg;
    wire        cs_registration_complete;
    wire        cs_registration_failed;

    wire [447:0] ev_to_cs_msg;
    wire         ev_to_cs_valid;
    wire [447:0] cs_to_ev_msg;
    wire         cs_to_ev_valid;

    // Mutual Authentication Wires
    wire ev_mutual_complete;
    wire cs_mutual_complete;
    
    // Pipeline Registers to simulate one-cycle communication delay
    reg [447:0] ev_to_cs_msg_pipe;
    reg         ev_to_cs_valid_pipe;
    reg [447:0] cs_to_ev_msg_pipe;
    reg         cs_to_ev_valid_pipe;

    // Authentication Process State
    reg [23:0]  auth_timeout_counter;
    reg         auth_in_progress;

    // Pipeline for message passing
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            ev_to_cs_msg_pipe <= 0;
            ev_to_cs_valid_pipe <= 0;
            cs_to_ev_msg_pipe <= 0;
            cs_to_ev_valid_pipe <= 0;
        end else begin
            ev_to_cs_msg_pipe <= ev_to_cs_msg;
            ev_to_cs_valid_pipe <= ev_to_cs_valid;
            cs_to_ev_msg_pipe <= cs_to_ev_msg;
            cs_to_ev_valid_pipe <= cs_to_ev_valid;
        end
    end

    // Authentication Timeout Counter
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            auth_timeout_counter <= 0;
            auth_in_progress <= 0;
        end else begin
            if (start_authentication && !auth_in_progress) begin
                auth_timeout_counter <= 0;
                auth_in_progress <= 1;
            end else if (auth_in_progress) begin
                if (mutual_auth_status) begin
                    auth_in_progress <= 0; // Process complete
                end else if (auth_timeout_counter < TIMEOUT_CYCLES) begin
                    auth_timeout_counter <= auth_timeout_counter + 1;
                end else begin
                    auth_in_progress <= 0; // Timeout occurred
                end
            end
        end
    end

    // ################### Module Instantiations ###################

    EV_USP_Registration ev_usp_reg_inst (
        .clk(clk),
        .rst(rst),
        .start_registration(start_registration_ev),
        .ev_raw_id_i(64'h1111_1111_1111_1111),
        .ev_raw_ch_i(64'hAAAA_BBBB_CCCC_DDDD),
        .ev_raw_pub_key_i(64'hEEEE_EEEE_EEEE_EEEE),
        .ev_raw_prv_key_i(64'hFFFF_FFFF_FFFF_FFFF),
        .usp_id_j_in(USP_ID_J),
        .ev_psidev_out(ev_psidev_reg),
        .ev_rs_out(ev_rs_reg),
        .ev_pub_key_out(ev_pub_key_reg),
        .ev_prv_key_out(ev_prv_key_reg),
        .registration_complete(ev_registration_complete),
        .registration_failed(ev_registration_failed)
    );

    CS_USP_Registration cs_usp_reg_inst (
        .clk(clk),
        .rst(rst),
        .start_registration(start_registration_cs),
        .cs_raw_id_k(64'h2222_2222_2222_2222),
        .cs_raw_pub_key_k(64'h1234_5678_9ABC_DEF0),
        .cs_raw_prv_key_k(64'h0FED_CBA9_8765_4321),
        .usp_id_j_in(USP_ID_J),
        .cs_id_out(cs_id_reg),
        .cs_pub_key_out(cs_pub_key_reg),
        .cs_prv_key_out(cs_prv_key_reg),
        .registration_complete(cs_registration_complete),
        .registration_failed(cs_registration_failed)
    );

    EV_Authentication_Module ev_auth_inst (
        .clk(clk),
        .rst(rst),
        .start_auth(start_authentication),
        .EV_PS_ID_SELF(ev_psidev_reg),
        .EV_PUB_KEY_SELF(ev_pub_key_reg),
        .EV_PRV_KEY_SELF(ev_prv_key_reg),
        .CS_PUB_KEY_KNOWN(cs_pub_key_reg),
        .CS_ID_KNOWN(cs_id_reg),
        .ev_rx_msg(cs_to_ev_msg_pipe),
        .ev_rx_valid(cs_to_ev_valid_pipe),
        .ev_tx_msg(ev_to_cs_msg),
        .ev_tx_valid(ev_to_cs_valid),
        .ev_auth_ok(ev_auth_status),
        .cs_auth_ok(cs_auth_status),
        .cs_mutual_auth_complete_in(cs_mutual_complete),
        .mutual_auth_complete(ev_mutual_complete)
    );

    CS_Authentication_Module cs_auth_inst (
        .clk(clk),
        .rst(rst),
        .start_auth(start_authentication),
        .CS_ID_SELF(cs_id_reg),
        .CS_PUB_KEY_SELF(cs_pub_key_reg),
        .CS_PRV_KEY_SELF(cs_prv_key_reg),
        .EV_PUB_KEY_KNOWN(ev_pub_key_reg),
        .EV_PS_ID_KNOWN(ev_psidev_reg),
        .cs_rx_msg(ev_to_cs_msg_pipe),
        .cs_rx_valid(ev_to_cs_valid_pipe),
        .cs_tx_msg(cs_to_ev_msg),
        .cs_tx_valid(cs_to_ev_valid),
        .cs_auth_ok(cs_auth_status),
        .ev_auth_ok(ev_auth_status),
        .mutual_auth_complete(cs_mutual_complete)
    );

    // Output Assignments
    assign ev_reg_status = ev_registration_complete;
    assign cs_reg_status = cs_registration_complete;
    assign mutual_auth_status = ev_mutual_complete && cs_mutual_complete;
    assign auth_process_active = auth_in_progress;

endmodule

//############################################################################
//
// Module: EV_USP_Registration
// Description: Handles the registration process for the Electric Vehicle (EV).
//
//############################################################################
module EV_USP_Registration (
    input  wire       clk,
    input  wire       rst,
    input  wire       start_registration,
    input  [63:0]     ev_raw_id_i,
    input  [63:0]     ev_raw_ch_i,
    input  [63:0]     ev_raw_pub_key_i,
    input  [63:0]     ev_raw_prv_key_i,
    input  [63:0]     usp_id_j_in,
    output reg [63:0] ev_psidev_out,
    output reg [63:0] ev_rs_out,
    output reg [63:0] ev_pub_key_out,
    output reg [63:0] ev_prv_key_out,
    output reg        registration_complete,
    output reg        registration_failed
);

    localparam [2:0] IDLE           = 3'b000;
    localparam [2:0] GENERATE_PSID  = 3'b001;
    localparam [2:0] GENERATE_RS    = 3'b010;
    localparam [2:0] KEY_GENERATION = 3'b011;
    localparam [2:0] COMPLETE       = 3'b100;
    localparam [2:0] FAILED         = 3'b101;

    reg [2:0] current_state;
    wire keygen_failed = 1'b0; // Placeholder

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            current_state <= IDLE;
            ev_psidev_out <= 0;
            ev_rs_out <= 0;
            ev_pub_key_out <= 0;
            ev_prv_key_out <= 0;
            registration_complete <= 0;
            registration_failed <= 0;
        end else begin
            case (current_state)
                IDLE: begin
                    registration_complete <= 0; // De-assert status flags
                    registration_failed <= 0;
                    if (start_registration) begin
                        current_state <= GENERATE_PSID;
                    end
                end
                
                GENERATE_PSID: begin
                    ev_psidev_out <= ev_raw_id_i ^ usp_id_j_in;
                    current_state <= GENERATE_RS;
                end
                
                GENERATE_RS: begin
                    ev_rs_out <= ev_raw_ch_i ^ ev_psidev_out;
                    current_state <= KEY_GENERATION;
                end
                
                KEY_GENERATION: begin
                    ev_pub_key_out <= ev_raw_pub_key_i;
                    ev_prv_key_out <= ev_raw_prv_key_i;
                    if (keygen_failed) begin
                        current_state <= FAILED;
                    end else begin
                        current_state <= COMPLETE;
                    end
                end
                
                COMPLETE: begin
                    registration_complete <= 1'b1;
                    // Stay in this state until reset
                end
                
                FAILED: begin
                    registration_failed <= 1'b1;
                    // Stay in this state until reset
                end

                default:
                    current_state <= IDLE;
            endcase
        end
    end
endmodule

//############################################################################
//
// Module: CS_USP_Registration
// Description: Handles the registration process for the Charging Station (CS).
//
//############################################################################
module CS_USP_Registration (
    input  wire       clk,
    input  wire       rst,
    input  wire       start_registration,
    input  [63:0]     cs_raw_id_k,
    input  [63:0]     cs_raw_pub_key_k,
    input  [63:0]     cs_raw_prv_key_k,
    input  [63:0]     usp_id_j_in,
    output reg [63:0] cs_id_out,
    output reg [63:0] cs_pub_key_out,
    output reg [63:0] cs_prv_key_out,
    output reg        registration_complete,
    output reg        registration_failed
);

    localparam [2:0] IDLE           = 3'b000;
    localparam [2:0] GENERATE_ID    = 3'b001;
    localparam [2:0] KEY_GENERATION = 3'b010;
    localparam [2:0] COMPLETE       = 3'b011;
    localparam [2:0] FAILED         = 3'b100;

    reg [2:0] current_state;
    wire keygen_failed = 1'b0; // Placeholder

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            current_state <= IDLE;
            cs_id_out <= 0;
            cs_pub_key_out <= 0;
            cs_prv_key_out <= 0;
            registration_complete <= 0;
            registration_failed <= 0;
        end else begin
            case (current_state)
                IDLE: begin
                    registration_complete <= 0; // De-assert status flags
                    registration_failed <= 0;
                    if (start_registration) begin
                        current_state <= GENERATE_ID;
                    end
                end
                
                GENERATE_ID: begin
                    cs_id_out <= cs_raw_id_k ^ usp_id_j_in;
                    current_state <= KEY_GENERATION;
                end
                
                KEY_GENERATION: begin
                    cs_pub_key_out <= cs_raw_pub_key_k;
                    cs_prv_key_out <= cs_raw_prv_key_k;
                    if (keygen_failed) begin
                        current_state <= FAILED;
                    end else begin
                        current_state <= COMPLETE;
                    end
                end
                
                COMPLETE: begin
                    registration_complete <= 1'b1;
                    // Stay in this state until reset
                end
                
                FAILED: begin
                    registration_failed <= 1'b1;
                    // Stay in this state until reset
                end
                
                default:
                    current_state <= IDLE;
            endcase
        end
    end
endmodule

//############################################################################
//
// Module: EV_Authentication_Module
// Description: State machine for EV-side authentication.
//
//############################################################################
module EV_Authentication_Module #(
    parameter TIMEOUT_CYCLES = 24'd25_000_000
) (
    input  wire       clk,
    input  wire       rst,
    input  wire       start_auth,
    input  [63:0]     EV_PS_ID_SELF,
    input  [63:0]     EV_PUB_KEY_SELF,
    input  [63:0]     EV_PRV_KEY_SELF,
    input  [63:0]     CS_PUB_KEY_KNOWN,
    input  [63:0]     CS_ID_KNOWN,
    input  [447:0]    ev_rx_msg,
    input  wire       ev_rx_valid,
    output reg [447:0]ev_tx_msg,
    output reg        ev_tx_valid,
    output reg        ev_auth_ok,
    input  wire       cs_auth_ok,
    input  wire       cs_mutual_auth_complete_in,
    output reg        mutual_auth_complete
);

    localparam [2:0] IDLE                       = 3'b000;
    localparam [2:0] INITIATE_AUTH              = 3'b001;
    localparam [2:0] WAIT_FOR_CS_RESPONSE       = 3'b010;
    localparam [2:0] VERIFY_CS                  = 3'b011;
    localparam [2:0] AWAIT_MUTUAL_CONFIRMATION  = 3'b100;
    localparam [2:0] MUTUAL_AUTH_SUCCESS        = 3'b101;
    localparam [2:0] AUTH_FAILED                = 3'b110;

    reg [2:0]  current_state, next_state;
    reg [23:0] timeout_counter;

    wire verification_passed = (ev_rx_msg[447:384] == CS_ID_KNOWN) && (ev_rx_msg[383:320] == CS_PUB_KEY_KNOWN);

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            current_state <= IDLE;
            timeout_counter <= 0;
            ev_tx_valid <= 0;
            ev_tx_msg <= 0;
            ev_auth_ok <= 0;
            mutual_auth_complete <= 0;
        end else begin
            current_state <= next_state;

            // Handle timeout counter
            if (next_state != current_state) begin // Reset counter on state change
                timeout_counter <= 0;
            end else if (current_state == WAIT_FOR_CS_RESPONSE || current_state == AWAIT_MUTUAL_CONFIRMATION) begin
                timeout_counter <= timeout_counter + 1;
            end
        end
    end

    always @(*) begin
        next_state = current_state;
        ev_tx_valid = 1'b0;
        ev_tx_msg = 448'b0;
        ev_auth_ok = 1'b0;
        mutual_auth_complete = 1'b0;

        case (current_state)
            IDLE:
                if (start_auth) begin
                    next_state = INITIATE_AUTH;
                end
            
            INITIATE_AUTH: begin
                ev_tx_valid = 1'b1;
                ev_tx_msg = {EV_PS_ID_SELF, EV_PUB_KEY_SELF, 320'd0};
                next_state = WAIT_FOR_CS_RESPONSE;
            end
            
            WAIT_FOR_CS_RESPONSE:
                if (ev_rx_valid) begin
                    next_state = VERIFY_CS;
                end else if (timeout_counter >= TIMEOUT_CYCLES) begin
                    next_state = AUTH_FAILED;
                end
            
            VERIFY_CS:
                if (verification_passed) begin
                    ev_auth_ok = 1'b1; // Signal that we have authenticated the CS
                    next_state = AWAIT_MUTUAL_CONFIRMATION;
                end else begin
                    next_state = AUTH_FAILED;
                end
            
            AWAIT_MUTUAL_CONFIRMATION: begin
                ev_auth_ok = 1'b1; // Keep signal asserted
                if (cs_auth_ok && cs_mutual_auth_complete_in) begin
                    next_state = MUTUAL_AUTH_SUCCESS;
                end else if (timeout_counter >= TIMEOUT_CYCLES) begin
                    next_state = AUTH_FAILED;
                end
            end
            
            MUTUAL_AUTH_SUCCESS: begin
                ev_auth_ok = 1'b1;
                mutual_auth_complete = 1'b1;
                next_state = IDLE;
            end
            
            AUTH_FAILED:
                next_state = IDLE;
            
            default:
                next_state = IDLE;
        endcase
    end
endmodule

//############################################################################
//
// Module: CS_Authentication_Module
// Description: State machine for CS-side authentication.
//
//############################################################################
module CS_Authentication_Module #(
    parameter TIMEOUT_CYCLES = 24'd25_000_000
) (
    input  wire       clk,
    input  wire       rst,
    input  wire       start_auth,
    input  [63:0]     CS_ID_SELF,
    input  [63:0]     CS_PUB_KEY_SELF,
    input  [63:0]     CS_PRV_KEY_SELF,
    input  [63:0]     EV_PUB_KEY_KNOWN,
    input  [63:0]     EV_PS_ID_KNOWN,
    input  [447:0]    cs_rx_msg,
    input  wire       cs_rx_valid,
    output reg [447:0]cs_tx_msg,
    output reg        cs_tx_valid,
    output reg        cs_auth_ok,
    input  wire       ev_auth_ok,
    output reg        mutual_auth_complete
);
    
    localparam [2:0] IDLE                       = 3'b000;
    localparam [2:0] WAIT_FOR_EV_REQUEST        = 3'b001;
    localparam [2:0] VERIFY_EV_AND_RESPOND      = 3'b010;
    localparam [2:0] AWAIT_MUTUAL_CONFIRMATION  = 3'b011;
    localparam [2:0] MUTUAL_AUTH_SUCCESS        = 3'b100;
    localparam [2:0] AUTH_FAILED                = 3'b101;

    reg [2:0]  current_state, next_state;
    reg [23:0] timeout_counter;

    wire verification_passed = (cs_rx_msg[447:384] == EV_PS_ID_KNOWN) && (cs_rx_msg[383:320] == EV_PUB_KEY_KNOWN);

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            current_state <= IDLE;
            timeout_counter <= 0;
        end else begin
            current_state <= next_state;

            // Handle timeout counter
            if (next_state != current_state) begin
                timeout_counter <= 0;
            end else if (current_state == WAIT_FOR_EV_REQUEST || current_state == AWAIT_MUTUAL_CONFIRMATION) begin
                timeout_counter <= timeout_counter + 1;
            end
        end
    end

    always @(*) begin
        next_state = current_state;
        cs_tx_valid = 1'b0;
        cs_tx_msg = 448'b0;
        cs_auth_ok = 1'b0;
        mutual_auth_complete = 1'b0;
        
        case (current_state)
            IDLE:
                if (start_auth) begin
                    next_state = WAIT_FOR_EV_REQUEST;
                end
            
            WAIT_FOR_EV_REQUEST:
                if (cs_rx_valid) begin
                    next_state = VERIFY_EV_AND_RESPOND;
                end else if (timeout_counter >= TIMEOUT_CYCLES) begin
                    next_state = AUTH_FAILED;
                end
            
            VERIFY_EV_AND_RESPOND:
                if (verification_passed) begin 
                    cs_tx_valid = 1'b1;
                    cs_tx_msg = {CS_ID_SELF, CS_PUB_KEY_SELF, 320'd0};
                    cs_auth_ok = 1'b1; // Signal that we have authenticated the EV
                    next_state = AWAIT_MUTUAL_CONFIRMATION;
                end else begin
                    next_state = AUTH_FAILED;
                end
            
            AWAIT_MUTUAL_CONFIRMATION: begin
                cs_auth_ok = 1'b1; // Keep signal asserted
                if (ev_auth_ok) begin // Wait for EV to confirm it has authenticated us
                    next_state = MUTUAL_AUTH_SUCCESS;
                end else if (timeout_counter >= TIMEOUT_CYCLES) begin
                    next_state = AUTH_FAILED;
                end
            end
            
            MUTUAL_AUTH_SUCCESS: begin
                cs_auth_ok = 1'b1;
                mutual_auth_complete = 1'b1;
                next_state = IDLE;
            end
            
            AUTH_FAILED:
                next_state = IDLE;
            
            default:
                next_state = IDLE;
        endcase
    end
endmodule
