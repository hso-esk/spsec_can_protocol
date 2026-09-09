# SPSEC CAN Protocol

This repository implements the core logic for mapping the abstract SPsec Sublayer (`SPsec302`) to the physical CAN FD transport layer.

This module focuses on the encoding the SPsec Data Plane and Control Plane messages into the CAN FD frames.

## CAN FD Mapping Details

### 1. Control Plane Mapping
The External Control Plane (which carries Handshakes, Sync messages, and Heartbeats) must coexist on the same wire as standard traffic without collision.
To guarantee this, SPsec302 utilizes **29-bit Extended CAN IDs with bit 25 set**. This cleanly isolates security-management frames from any standard J1939 FD or CANopen FD traffic.

### 2. Data Plane Payload Reduction
To construct a "Secured Addressed Data Unit," the Data Plane must append a Security Stamp to the payload to guarantee authenticity and integrity.
Because a CAN FD data field is capped at 64 bytes, and the Security Stamp requires the last 10 bytes of the frame, the maximum allowable payload size for the application layer is actively constrained to **54 bytes** (or often limited to 48 bytes for implementation simplicity).

### 3. Nonce Construction Constraints
Cryptographic primitives utilized by the `common` layer require a Nonce (Number Used Once). When mapped to CAN FD, the SPsec protocol constructs this Nonce deterministically to save overhead over the wire:
1. The lowest bits are populated with the current synchronized **64-bit timestamp**.
2. The next 16 bits are the **CAN ID** of the message itself (preventing collisions if two Participants transmit at the exact same microsecond).
3. Remaining bits are padded using the **pre-shared Salt** of the active key.

## Functional Components
- **CAN Protocol Mapping**: Encapsulating/extracting payloads onto the wire (`spsec_protocol_can.c`).
- **Handshake Protocol**: Orchestrating the exchange over CAN to negotiate keys (`protocol_handshake.c`).
- **Session Handling**: Transporting Heartbeats and time sync packets (`protocol_session.c`).
- **Register Operations**: Processing configuration reads and writes mapped over the CAN bus (`protocol_register.c`).