AGENT.md - Project Zero-Trust DB Proxy
> Amendment 2026-08-11: Redis → **Valkey** (drop-in RESP-compatible fork, license-friendly) per user directive. Full amendment list in hermes-agent-spec.md §9.

1. Project Overview
This project is a Zero-Trust, Just-in-Time (JIT) Database Access Gateway designed to sit between end-users (using thick clients like HeidiSQL) and backend databases (MySQL/PostgreSQL).

It replaces static database credentials with a dynamic, token-based system. It features real-time query auditing (Maker-Checker principle) and integrates with an external Ticketing/Orchestration system via a direct API call.

Architecture Paradigm: The system is distributed, separating the Control Plane (UI/API) from the Data Plane (TCP Proxy) across different servers to allow independent scaling and network isolation.

2. Architecture Summary
The system is divided into two independently deployable servers, communicating via a shared Redis instance:

Control Plane Server (Web/API):
Serves the Angular SPA.
Exposes a secure API endpoint that accepts routing details (username, db_user, db_ip, db_port) and generates a short-lived, single-use token.
Writes tokens to Redis.
Hosts the WebSocket server for the Checker Dashboard. Subscribes to Redis Pub/Sub to receive live queries from the Data Plane.
Data Plane Server (TCP Proxy):
Listens for raw TCP database traffic from HeidiSQL.
Validates incoming connection tokens against Redis and retrieves the db_ip/db_port routing details.
Connects to the backend database and pipes traffic.
Parses binary database protocols (MySQL/Postgres) to extract SQL queries.
Publishes extracted SQL queries to Redis Pub/Sub.
Shared Infrastructure:
Valkey: Acts as the single source of truth for short-lived tokens (with TTLs) and the message broker for the Maker-Checker live query feed.
Core Operational Flow
API Request: The external Ticketing System (or user via UI) sends a POST /api/token request to the Control Plane containing username, db_user, db_ip, and db_port.
Token Generation: Control Plane API generates a short-lived (5 min), single-use token and stores the payload in Valkey.
Client Connection: User copies the Token, Host, and Port into HeidiSQL, connecting directly to the Data Plane server.
Proxying & Parsing: The Data Plane TCP Proxy intercepts the connection, validates the token against Valkey, retrieves the target db_ip and db_port, connects to the backend DB, and parses all SQL traffic.
Live Auditing: The Data Plane publishes parsed SQL queries to Valkey Pub/Sub. The Control Plane WebSocket server picks them up and streams them to the Checker's Angular Dashboard.
3. Tech Stack & Recommended Libraries (Enterprise LTS - Aug 2026)
Backend (Go)
Language: Go 1.27 (Latest fully supported, battle-tested release).
Control Plane HTTP Router: Standard net/http (Go 1.27's native ServeMux) or labstack/echo/v4.
WebSocket (Control Plane): coder/websocket (v2.x+) - Context-aware WebSocket library.
Shared State & Messaging: valkey-io/valkey-go (v1.x) - Official Valkey client. Used for token TTLs and Pub/Sub.
Configuration: spf13/viper (v1.19+).
Logging: log/slog (Standard Library) - High-performance structured logging.
Frontend (Angular LTS)
Framework: Angular 21 (Official LTS). Standalone Components, Zoneless change detection, Signals-based reactivity.
UI Library: NG-ZORRO v21.x.
State Management: ngrx/component-store (v21.x) or Angular Signals.
Clipboard Utility: ngx-clipboard (v17+).
WebSocket Client: rxjs/webSocket (RxJS v8).
4. Recommended Project Structure (Monorepo)
Because the planes are separated, the Go codebase is split into distinct entry points and shared internal packages.

text

db-proxy-project/
├── cmd/
│   ├── control/                 # Control Plane Entry Point
│   │   └── main.go              # Starts HTTP API, WebSockets
│   └── data/                    # Data Plane Entry Point
│       └── main.go              # Starts TCP Proxy Listener
├── internal/
│   ├── api/                     # HTTP Handlers, WebSockets (Control Plane)
│   │   ├── handlers.go          # Contains POST /api/token logic
│   │   └── websocket.go
│   ├── proxy/                   # TCP Proxy & Protocol Parsing (Data Plane)
│   │   ├── listener.go          # TCP Server
│   │   ├── mysql_parser.go      # MySQL packet parsing
│   │   ├── postgres_parser.go   # Postgres packet parsing
│   │   └── router.go            # Token validation (via Redis) & Backend routing
│   ├── store/                   # Valkey interfaces (Shared by both planes)
│   │   ├── valkey_store.go       # Token Set/Get
│   │   └── pubsub.go            # Publish/Subscribe for queries
│   └── models/                  # Shared structs (TokenPayload, QueryEvent)
│       └── models.go
├── web/                         # Angular 21 Frontend Project (Served by Control Plane)
│   ├── src/
│   │   ├── app/
│   │   │   ├── core/            # Services (ApiService, LiveQueryService)
│   │   │   ├── features/
│   │   │   │   ├── maker-portal/ # Token generation UI
│   │   │   │   └── checker-dashboard/ # Live WebSocket query feed
│   │   │   └── shared/          # NG-ZORRO shared modules
│   │   └── styles.scss
│   ├── angular.json
│   └── package.json
├── configs/
│   ├── control.yaml             # Control Plane config (API Port, Redis)
│   └── data.yaml                # Data Plane config (TCP Port, Redis)
├── go.mod
└── AGENT.md
5. Development Guidelines for Agents
General
Decoupling: The Data Plane must NEVER make HTTP calls to the Control Plane. All state sharing (tokens) and event streaming (queries) MUST go through Valkey. This ensures the Data Plane can scale independently and survive Control Plane restarts.
Protocol Awareness: The Data Plane is NOT a blind TCP pipe. It must read 4-byte headers (3 bytes length, 1 byte sequence) to parse MySQL packets. Always parse payloads to extract COM_QUERY (byte 0x03).
Security First: Tokens must be strictly single-use and short-lived. The Control Plane writes them to Valkey with a 5-minute TTL. The Data Plane reads and immediately deletes the token (atomic GETDEL). The POST /api/token endpoint on the Control Plane MUST be secured (API key or UI session) to prevent unauthorized token generation.
Go Routines & Context: Use goroutines for bidirectional TCP piping. Ensure channels and connections are properly closed to prevent memory leaks. Use context.Context for cancellation and timeouts.
Backend (Go 1.27)
Use log/slog for all logging. Pass loggers via context where appropriate.
Token Payload Structure: The Redis token payload must map exactly to the API request:
go

type TokenPayload struct {
    Username string `json:"username"` // AD User (for auditing)
    DBUser   string `json:"db_user"`  // Backend DB User
    DBIP     string `json:"db_ip"`    // Backend DB IP
    DBPort   string `json:"db_port"`  // Backend DB Port
    TicketID string `json:"ticket_id"` // Optional, for Maker-Checker grouping
}
Control Plane WebSockets: Use coder/websocket. When a Checker connects, spawn a goroutine that subscribes to the specific Valkey Pub/Sub channel (e.g., queries:TICKET-1 or queries:alice) and forwards messages to the WebSocket.
Data Plane Pub/Sub: When a query is parsed, use Valkey Publish to send the QueryEvent JSON to the corresponding channel.
Frontend (Angular 21 + NG-ZORRO)
Standalone Components: Do NOT use NgModule. All components and routes must be Standalone.
Control Flow: Use Angular 21's built-in control flow syntax (@if, @for, @switch).
Reactivity: Leverage Angular Signals for local state management in the Maker Portal. Use toSignal to bridge RxJS WebSocket streams to Signals for the Checker Dashboard UI.
UI Consistency: Use NG-ZORRO components (nz-table, nz-card, nz-select, nz-tag) for a unified enterprise look.
WebSocket Management: In the LiveQueryService, ensure the WebSocket subject is properly completed (socket$.complete()) when the user navigates away from the Checker Dashboard to prevent memory leaks.
6. Deployment & Running (Mental Model)
Build Frontend: cd web && npm run build (Outputs to web/dist/<project-name>/browser/).
Deploy Control Plane: Run go run cmd/control/main.go on Server A. It serves the Angular files on :8080 and connects to Redis.
Deploy Data Plane: Run go run cmd/data/main.go on Server B. It listens for TCP traffic on :3306 and connects to Redis.
Generate Token (API Call):
bash

curl -X POST http://<server-a>:8080/api/token \
-H "Content-Type: application/json" \
-d '{
  "username": "alice", 
  "db_user": "readonly_user", 
  "db_ip": "10.0.0.5", 
  "db_port": "3306"
}'
# Returns: {"token": "sess_8f3a9b", "host": "<server-b>", "port": "3306"}
User Flow: User takes the returned token, pastes it into HeidiSQL (as the username) targeting <server-b>:3306.
Checker Flow: Open http://<server-a>:8080/checker, enter alice or the ticket ID, watch queries stream in via the Control Plane WebSocket (fed by the Data Plane through Redis).



