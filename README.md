# EZ-Access – Lightweight MQTT Protocol & Broker Implementation

EZ-Access is a minimal yet robust implementation of the MQTT 3.1.1 protocol, built entirely from scratch in C.
It provides both the protocol library (packet parsing/packing) and a fully functional broker for lightweight message distribution, suitable for embedded devices or resource-constrained systems.

**🚀 Features:**
- Implements core MQTT 3.1.1 packet types for QOS 0/1:
- CONNECT, CONNACK
- PUBLISH, PUBACK
- SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK
- PINGREQ, PINGRESP, DISCONNECT (To be added...)

**Broker Implementation:**
- Subscription management
- Message routing based on topics (Wildcard matching to be added in future versions...)
- Session state handling (clean session only, QoS 0/1)

**📖 Project Structure:**
```text
EZ-Access/
│
├── mqtt_protocol_lib/       # Protocol library
│   ├── main/include/        # Public headers (protocol, utils)
│   ├── main/src/            # Implementation files
│   └── Makefile             # Builds static library
│
├── broker/                  # Broker implementation
│   ├── main/include/        # Broker headers
│   ├── main/src/            # Broker source (mqtt_server.c, etc.)
│   └── Makefile             # Builds and runs broker (links the mqtt library)
```

**Requirements:**
- Compiler: gcc or compatible C compiler
- POSIX-compliant system (Linux, macOS; Windows via WSL or MinGW)
- CMake / Make (for building)

**⚙️ Building:**
1. *Build protocol library*
```text
|------------------------|
| > cd mqtt_protocol_lib |
| > make                 |
| > cd ..                |
|________________________|
```
2. *Build and run broker:*
```text
|------------------|
| > cd mqtt_broker |
| > make run       |
|__________________|
```
By default, the broker listens on port **1883**.
You can connect using any MQTT client (e.g., mosquitto_pub, mosquitto_sub) or your custom publisher/subscriber implementations.

**🗺️ Planned roadmap:**
- Add support for wildcard matching of topic filters.
- Add pingreq/pingresp and automatically disconnect clients after long periods of inactivity.
- Implement clean-session, add retained messages.
- Extend publisher/subscriber example apps

**Implementation notes:**
- No QOS 2 support.
- No will.
- No authentication (username/pwd).

*Written in ANSI C (POSIX sockets for networking)*
