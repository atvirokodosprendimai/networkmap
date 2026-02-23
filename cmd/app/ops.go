package main

import (
	"context"
	"fmt"
	"net/http"
)

func doLogin(ctx context.Context, cfg cliConfig, email, password, tokenName string, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "auth.login", map[string]any{
			"email":      email,
			"password":   password,
			"token_name": tokenName,
		}, out)
	}
	client := newAPIClient(cfg.Server, "")
	return client.request(ctx, http.MethodPost, "/api/auth/login", map[string]any{
		"email":      email,
		"password":   password,
		"mode":       "token",
		"token_name": tokenName,
	}, out)
}

func doWhoAmI(ctx context.Context, cfg cliConfig, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "auth.whoami", map[string]any{"token": cfg.Token}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	return client.request(ctx, http.MethodGet, "/api/auth/whoami", nil, out)
}

func doLogout(ctx context.Context, cfg cliConfig) error {
	if cfg.Transport == "uds" {
		return nil
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	return client.request(ctx, http.MethodPost, "/api/auth/logout", nil, nil)
}

func doObjectsList(ctx context.Context, cfg cliConfig, typeID *uint, q string, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "objects.list", map[string]any{"token": cfg.Token, "type_id": typeID, "q": q, "limit": 200}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	path := "/api/entities"
	params := ""
	if typeID != nil {
		params += "type_id=" + uintToString(*typeID)
	}
	if q != "" {
		if params != "" {
			params += "&"
		}
		params += "q=" + q
	}
	if params != "" {
		path += "?" + params
	}
	return client.request(ctx, http.MethodGet, path, nil, out)
}

func doObjectsCreate(ctx context.Context, cfg cliConfig, entityTypeID uint, name, status string, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "objects.create", map[string]any{"token": cfg.Token, "entity_type_id": entityTypeID, "name": name, "status": status}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	return client.request(ctx, http.MethodPost, "/api/entities", map[string]any{"entity_type_id": entityTypeID, "name": name, "status": status}, out)
}

func doEdgesConnect(ctx context.Context, cfg cliConfig, from, relationID, to uint, directed bool, state string, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "edges.connect", map[string]any{"token": cfg.Token, "from": from, "relation_id": relationID, "to": to, "directed": directed, "state": state}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	return client.request(ctx, http.MethodPost, "/api/edges/connect", map[string]any{"from": from, "relation_id": relationID, "to": to, "directed": directed, "state": state}, out)
}

func doEdgesCut(ctx context.Context, cfg cliConfig, edgeID uint, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "edges.cut", map[string]any{"token": cfg.Token, "edge_id": edgeID}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	return client.request(ctx, http.MethodPost, "/api/edges/cut", map[string]any{"edge_id": edgeID}, out)
}

func doTrace(ctx context.Context, cfg cliConfig, from uint, targetID *uint, depth int, relations string, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "trace.run", map[string]any{"token": cfg.Token, "start_entity_id": from, "target_entity_id": targetID, "max_depth": depth, "relation_keys": relations}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	payload := map[string]any{"start_entity_id": from, "max_depth": depth, "relation_keys": relations}
	if targetID != nil {
		payload["target_entity_id"] = *targetID
	}
	return client.request(ctx, http.MethodPost, "/api/trace", payload, out)
}

func doEntityTypesList(ctx context.Context, cfg cliConfig, q string, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "types.entity.list", map[string]any{"token": cfg.Token, "q": q}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	path := "/api/catalog/entity-types"
	if q != "" {
		path += "?q=" + q
	}
	return client.request(ctx, http.MethodGet, path, nil, out)
}

func doEntityTypesCreate(ctx context.Context, cfg cliConfig, key, name, description string, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "types.entity.create", map[string]any{"token": cfg.Token, "key": key, "name": name, "description": description}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	return client.request(ctx, http.MethodPost, "/api/catalog/entity-types", map[string]any{"key": key, "name": name, "description": description}, out)
}

func doRelationTypesList(ctx context.Context, cfg cliConfig, q string, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "types.relation.list", map[string]any{"token": cfg.Token, "q": q}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	path := "/api/catalog/relation-types"
	if q != "" {
		path += "?q=" + q
	}
	return client.request(ctx, http.MethodGet, path, nil, out)
}

func doRelationTypesCreate(ctx context.Context, cfg cliConfig, key, name, description string, directed bool, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "types.relation.create", map[string]any{"token": cfg.Token, "key": key, "name": name, "description": description, "directed": directed}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	return client.request(ctx, http.MethodPost, "/api/catalog/relation-types", map[string]any{"key": key, "name": name, "description": description, "directed": directed}, out)
}

func doAttributeDefsList(ctx context.Context, cfg cliConfig, scope, q string, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "types.attribute.list", map[string]any{"token": cfg.Token, "scope": scope, "q": q}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	path := "/api/catalog/attribute-defs"
	params := ""
	if scope != "" {
		params += "scope=" + scope
	}
	if q != "" {
		if params != "" {
			params += "&"
		}
		params += "q=" + q
	}
	if params != "" {
		path += "?" + params
	}
	return client.request(ctx, http.MethodGet, path, nil, out)
}

func doAttributeDefsUpsert(ctx context.Context, cfg cliConfig, scope, key, valueKind, description string, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "types.attribute.upsert", map[string]any{"token": cfg.Token, "scope": scope, "key": key, "value_kind": valueKind, "description": description}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	return client.request(ctx, http.MethodPost, "/api/catalog/attribute-defs", map[string]any{"scope": scope, "key": key, "value_kind": valueKind, "description": description}, out)
}

func doUsersList(ctx context.Context, cfg cliConfig, q string, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "access.user.list", map[string]any{"token": cfg.Token, "q": q}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	path := "/api/access/users"
	if q != "" {
		path += "?q=" + q
	}
	return client.request(ctx, http.MethodGet, path, nil, out)
}

func doUsersCreate(ctx context.Context, cfg cliConfig, email, password string, roleID uint, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "access.user.create", map[string]any{"token": cfg.Token, "email": email, "password": password, "role_id": roleID}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	return client.request(ctx, http.MethodPost, "/api/access/users", map[string]any{"email": email, "password": password, "role_id": roleID}, out)
}

func doRolesList(ctx context.Context, cfg cliConfig, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "access.role.list", map[string]any{"token": cfg.Token}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	return client.request(ctx, http.MethodGet, "/api/access/roles", nil, out)
}

func doAssignRole(ctx context.Context, cfg cliConfig, userID, roleID uint, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "access.role.assign", map[string]any{"token": cfg.Token, "user_id": userID, "role_id": roleID}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	return client.request(ctx, http.MethodPost, "/api/access/assign-role", map[string]any{"user_id": userID, "role_id": roleID}, out)
}

func doAuditList(ctx context.Context, cfg cliConfig, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		return client.call(ctx, "audit.list", map[string]any{"token": cfg.Token}, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	return client.request(ctx, http.MethodGet, "/api/audit/logs", nil, out)
}

func doWorkflowProvisionChain(ctx context.Context, cfg cliConfig, in map[string]any, out any) error {
	if cfg.Transport == "uds" {
		client := newRPCClient(cfg.Socket)
		payload := map[string]any{"token": cfg.Token}
		for k, v := range in {
			payload[k] = v
		}
		return client.call(ctx, "workflow.chain.provision", payload, out)
	}
	client := newAPIClient(cfg.Server, cfg.Token)
	return client.request(ctx, http.MethodPost, "/api/workflows/provision-chain", in, out)
}

func uintToString(v uint) string {
	return fmt.Sprintf("%d", v)
}
