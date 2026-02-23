# CLI Workflow: Build IPTV Chain (STB -> Router -> ONU -> GPON)

This guide shows the full CLI workflow for your scenario:

- create object types (`stb`, `router`, `onu`, `gpon_device`, plus location types)
- create connection types (`wire`, `fiber`, `installed_at`, `located_in`)
- create objects/entities
- link them together
- set EAV attributes (serial, MAC, other)
- query and verify the topology

It also includes a flexible one-shot chain helper at the end.

## 0) Start server and login

```bash
networkmap server
```

In another terminal:

```bash
networkmap auth login --email admin@networkmap.local --password admin
networkmap auth whoami
```

## 1) Create entity types (objects)

```bash
networkmap catalog entity-types create --key stb --name "STB"
networkmap catalog entity-types create --key router --name "Router"
networkmap catalog entity-types create --key onu --name "ONU"
networkmap catalog entity-types create --key gpon_device --name "GPON Device"
networkmap catalog entity-types create --key house --name "House"
networkmap catalog entity-types create --key street --name "Street"
```

Check:

```bash
networkmap catalog entity-types list
```

## 2) Create relation types (connections)

`wire` and `fiber` are relation types (links), not entity/object types.

```bash
networkmap catalog relation-types create --key wire --name "Wire"
networkmap catalog relation-types create --key fiber --name "Fiber"
networkmap catalog relation-types create --key installed_at --name "Installed At" --directed
networkmap catalog relation-types create --key located_in --name "Located In" --directed
```

Check:

```bash
networkmap catalog relation-types list
```

## 3) Create EAV attribute definitions

```bash
networkmap catalog attribute-defs upsert --scope entity --key serial_number --value-kind string --description "Device serial"
networkmap catalog attribute-defs upsert --scope entity --key mac_address --value-kind string --description "Device MAC"
networkmap catalog attribute-defs upsert --scope entity --key vendor --value-kind string
networkmap catalog attribute-defs upsert --scope entity --key model --value-kind string
```

Check:

```bash
networkmap catalog attribute-defs list --scope entity
```

## 4) Resolve IDs for types and relations

You can use `--json` and pick IDs from output.

```bash
networkmap catalog entity-types list --json
networkmap catalog relation-types list --json
networkmap catalog attribute-defs list --scope entity --json
```

From these results, note IDs for:

- entity types: `stb`, `router`, `onu`, `gpon_device`, `house`, `street`
- relation types: `wire`, `fiber`, `installed_at`, `located_in`
- attribute defs: `serial_number`, `mac_address`, optional others

## 5) Create entities (objects)

Use the correct `--type-id` values from step 4.

```bash
networkmap objects create --type-id <street_type_id> --name "ABC Street"
networkmap objects create --type-id <house_type_id> --name "House 5"

networkmap objects create --type-id <stb_type_id> --name "STB-H5"
networkmap objects create --type-id <router_type_id> --name "RTR-H5"
networkmap objects create --type-id <onu_type_id> --name "ONU-H5"
networkmap objects create --type-id <gpon_type_id> --name "GPON-ABC-5"
```

Check:

```bash
networkmap objects list
networkmap objects list --q H5
```

## 6) Link topology with edges

Use object IDs and relation IDs from listing outputs.

Address/location links:

```bash
networkmap edges connect --from <house_id> --relation-id <located_in_relation_id> --to <street_id> --directed
networkmap edges connect --from <stb_id> --relation-id <installed_at_relation_id> --to <house_id> --directed
networkmap edges connect --from <router_id> --relation-id <installed_at_relation_id> --to <house_id> --directed
networkmap edges connect --from <onu_id> --relation-id <installed_at_relation_id> --to <house_id> --directed
```

Service chain links:

```bash
networkmap edges connect --from <stb_id> --relation-id <wire_relation_id> --to <router_id>
networkmap edges connect --from <router_id> --relation-id <wire_relation_id> --to <onu_id>
networkmap edges connect --from <onu_id> --relation-id <fiber_relation_id> --to <gpon_id>
```

## 7) Set EAV values on STB (serial/MAC/other)

Use API (currently no dedicated CLI subcommand for set-attribute).

```bash
curl -sS -X POST http://127.0.0.1:8080/api/entities/attributes \
  -H "Authorization: Bearer <your_cli_token>" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": <stb_id>, "attr_def_id": <serial_attr_def_id>, "value": "SN123456"}'

curl -sS -X POST http://127.0.0.1:8080/api/entities/attributes \
  -H "Authorization: Bearer <your_cli_token>" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": <stb_id>, "attr_def_id": <mac_attr_def_id>, "value": "AA:BB:CC:DD:EE:FF"}'
```

Get token from local CLI config if needed:

```bash
cat ~/.networkmap/config.json
```

## 8) Query and verify

Trace end-to-end path:

```bash
networkmap trace --from <stb_id> --to <gpon_id> --depth 8
```

Trace constrained by relation keys:

```bash
networkmap trace --from <stb_id> --to <gpon_id> --relations wire,fiber --depth 8
```

Inventory checks:

```bash
networkmap objects list --q "House 5"
networkmap objects list --q "ABC Street"
networkmap objects list --q "STB-H5"
```

Audit checks:

```bash
networkmap audit list
```

## 9) Optional one-shot chain helper (flexible)

If you want fast provisioning without manual per-step connect:

```bash
networkmap workflow provision-chain \
  --nodes "stb:STB-H5,router:RTR-H5,onu:ONU-H5,gpon_device:GPON-ABC-5" \
  --relations "wire,wire,fiber" \
  --attrs "STB-H5:serial_number=SN123456,mac_address=AA:BB:CC:DD:EE:FF;ONU-H5:vendor=ZTE" \
  --state active
```

This helper is generic:

- it does not hardcode IPTV-only types/relations
- it auto-creates missing entity/relation types by key
- it creates or reuses entities by `type_key + entity_name`
- it creates edges in sequence (node[0] -> node[1] -> ...)

## Notes

- Prefer creating `wire`/`fiber` as relation types, not object types.
- For strict reproducibility in scripts, use `--json` and parse IDs.
- The default `networkmap` command now shows help when run without args.
