# NetworkMap - Fiber Network Topology Mapping, Inventory, and Traceability (Go + SQLite)

NetworkMap is a local-first network management system for ISP and enterprise teams that need reliable **fiber topology mapping**, **FTTH/GPON path tracing**, **network inventory**, and **audit-friendly operations**.

It combines a web GUI, CLI, and JSON-RPC API in one Go codebase using hexagonal architecture.

## Why NetworkMap

- Map physical and logical links as graph triples (subject -> relation -> object)
- Keep flexible device metadata with EAV attributes (serial, MAC, vendor, model, etc.)
- Trace service paths quickly (for outages, incident response, provisioning checks)
- Use both GUI and CLI with parity for day-to-day operations
- Run locally with SQLite (CGO-free) and no heavy infrastructure requirements

## Core Features

- **Graph Model:** entities, relation types, edges, recursive path trace
- **Flexible Attributes (EAV):** entity and edge attributes with typed definitions
- **Auth + RBAC + Audit:** users, roles, permissions, action logs
- **Web GUI:** Datastar + templ + Tailwind + Flowbite components
- **CLI:** human-readable tables by default, `--json` for automation
- **JSON-RPC v2 (Unix socket):** fast local CLI/server communication

## Tech Stack

- Go
- `chi` HTTP router
- `urfave/cli/v3`
- `gorm.io/gorm` + SQLite driver `modernc.org/sqlite` (no CGO)
- Goose migrations
- templ + Datastar + Flowbite

## Architecture

- `internal/domain` - domain models and repository ports
- `internal/application` - use-case/business logic
- `internal/adapters/db/sqlite` - persistence adapter + migrations
- `internal/adapters/http` - GUI + REST API adapter
- `internal/adapters/rpcjson` - JSON-RPC adapter
- `cmd/app` - binary entrypoint (server + CLI)

## Quick Start

### 1) Run server

```bash
networkmap server
```

Default bootstrap admin:

- email: `admin@networkmap.local`
- password: `admin`

### 2) Login from CLI

```bash
networkmap auth login --email admin@networkmap.local --password admin
networkmap auth whoami
```

### 3) Open GUI

- `http://127.0.0.1:8080/login`

## CLI Workflow for Real Provisioning

For a full real-world example (create object types, connection types, entities, links, attributes, and trace queries), see:

- `specs/cliworkflow.md`

That guide covers scenarios like:

- STB -> Router -> ONU -> GPON service chain
- House/street location linking
- serial number, MAC address, and extra EAV metadata

## Flexible Chain Provisioning (CLI)

You can provision any chain (not hardcoded IPTV) with:

```bash
networkmap workflow provision-chain \
  --nodes "stb:STB-H5,router:RTR-H5,onu:ONU-H5,gpon_device:GPON-ABC-5" \
  --relations "wire,wire,fiber" \
  --attrs "STB-H5:serial_number=SN123456,mac_address=AA:BB:CC:DD:EE:FF" \
  --state active
```

Format rules:

- `--nodes`: `type_key:EntityName,type_key:EntityName,...`
- `--relations`: relation key list between each adjacent node
- `--attrs`: `EntityName:key=value,key=value;EntityName:key=value`

## Development

### Generate templates and test

```bash
templ generate
go test ./...
```

### Migrations

Goose migrations are run by server startup in the SQLite adapter.

## Project Specs

- UI/UX implementation spec: `specs/ui.md`
- CLI operator workflow spec: `specs/cliworkflow.md`

## Notes

- Running `networkmap` without arguments now shows help.
- For automation, prefer `--json` on CLI commands.
- `wire` and `fiber` are typically relation types (links), not device types.
