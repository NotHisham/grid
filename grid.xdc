# Clock Source (50 MHz derived from 125 MHz)
create_clock -period 20.000 -name clk [get_ports clk]

# Input Ports (with specific I/O standards and pin assignments)
# Assuming F23 is a valid LVDS pin for clock input (Bank 64, Clock pins)
set_property -dict {PACKAGE_PIN F23 IOSTANDARD LVDS} [get_ports clk]          ;# 125 MHz clock source, Bank 64, divided to 50 MHz

# Check validity for the following pins. Let's assume you are using pins on Bank 65 for general I/O
set_property -dict {PACKAGE_PIN H17 IOSTANDARD LVCMOS33} [get_ports rst]      ;# Reset, Bank 65, Switch 0 (valid LVCMOS33 pin)
set_property -dict {PACKAGE_PIN G17 IOSTANDARD LVCMOS33} [get_ports start_registration_ev] ;# Start Registration EV, Bank 65, Switch 1 (verify pin availability)
set_property -dict {PACKAGE_PIN K13 IOSTANDARD LVCMOS33} [get_ports start_registration_cs] ;# Start Registration CS, Bank 65, Switch 2 (verify pin availability)
set_property -dict {PACKAGE_PIN M20 IOSTANDARD LVCMOS33} [get_ports start_authentication] ;# Start Authentication, Bank 65, Switch 3 (verify pin availability)

# Output Ports (LED indicators, LVCMOS33 I/O standard)
set_property -dict {PACKAGE_PIN L17 IOSTANDARD LVCMOS33} [get_ports ev_reg_status]    ;# Bank 65, LED 0
set_property -dict {PACKAGE_PIN K18 IOSTANDARD LVCMOS33} [get_ports cs_reg_status]    ;# Bank 65, LED 1
set_property -dict {PACKAGE_PIN J18 IOSTANDARD LVCMOS33} [get_ports ev_auth_status]   ;# Bank 65, LED 2
set_property -dict {PACKAGE_PIN H18 IOSTANDARD LVCMOS33} [get_ports cs_auth_status]   ;# Bank 65, LED 3
set_property -dict {PACKAGE_PIN M19 IOSTANDARD LVCMOS33} [get_ports mutual_auth_status] ;# Bank 65, LED 4
set_property -dict {PACKAGE_PIN N19 IOSTANDARD LVCMOS33} [get_ports auth_process_active] ;# Bank 65, LED 5

# Important: Check pinout for each pin assigned above and confirm its validity!
