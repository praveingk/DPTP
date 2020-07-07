# Documentation for DPTP (P4_16)

## Code Organization

### 1) DPTP Simple Switch : dptp_simple_switch.p4
    Dptp_switch is a simple mac-based forwarding switch which supports DPTP. 
    This reference switch code provides insights on how to integrate DPTP into any p4 code.

### 2) DPTP Core Modules : dptp.p4 | dptp_headers.p4 | dptp_parser.p4
    This code contains the core DPTP funtional modules for headers, parsers and pipeline. 