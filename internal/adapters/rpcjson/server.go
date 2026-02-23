package rpcjson

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/atvirokodosprendimai/networkmap/internal/application"
	"github.com/atvirokodosprendimai/networkmap/internal/domain"
)

type Server struct {
	service  *application.GraphService
	listener net.Listener
	path     string
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      any             `json:"id"`
}

type response struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  any         `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func Start(path string, service *application.GraphService) (*Server, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("rpc socket path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, err
	}

	s := &Server{service: service, listener: ln, path: path}
	go s.serve()
	return s, nil
}

func (s *Server) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *Server) Close() error {
	err := s.listener.Close()
	_ = os.Remove(s.path)
	return err
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	for {
		var req request
		if err := dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			_ = enc.Encode(response{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}, ID: nil})
			return
		}

		resp := s.dispatch(context.Background(), req)
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
}

func (s *Server) dispatch(ctx context.Context, req request) response {
	if req.JSONRPC != "2.0" || strings.TrimSpace(req.Method) == "" {
		return response{JSONRPC: "2.0", Error: &rpcError{Code: -32600, Message: "invalid request"}, ID: req.ID}
	}

	switch req.Method {
	case "auth.login":
		return s.handleAuthLogin(ctx, req)
	case "auth.whoami":
		identity, rpcResp, ok := s.authz(ctx, req, "")
		if !ok {
			return rpcResp
		}
		return response{JSONRPC: "2.0", Result: map[string]any{"id": identity.User.ID, "email": identity.User.Email}, ID: req.ID}
	case "objects.list":
		identity, rpcResp, ok := s.authz(ctx, req, "graph.read")
		if !ok {
			return rpcResp
		}
		_ = identity
		var p struct {
			Token  string `json:"token"`
			TypeID *uint  `json:"type_id"`
			Q      string `json:"q"`
			Limit  int    `json:"limit"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		entities, err := s.service.ListEntities(ctx, p.TypeID, p.Q, p.Limit)
		if err != nil {
			return internalError(req.ID, err)
		}
		return response{JSONRPC: "2.0", Result: entities, ID: req.ID}
	case "objects.create":
		identity, rpcResp, ok := s.authz(ctx, req, "graph.write")
		if !ok {
			return rpcResp
		}
		var p struct {
			Token        string `json:"token"`
			EntityTypeID uint   `json:"entity_type_id"`
			Name         string `json:"name"`
			Status       string `json:"status"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		out, err := s.service.CreateEntity(ctx, p.EntityTypeID, p.Name, p.Status)
		if err != nil {
			return appError(req.ID, err)
		}
		s.service.WriteAudit(ctx, &identity.User.ID, "graph.entity.create", "entity", &out.ID, "rpc")
		return response{JSONRPC: "2.0", Result: out, ID: req.ID}
	case "types.entity.list":
		_, rpcResp, ok := s.authz(ctx, req, "graph.read")
		if !ok {
			return rpcResp
		}
		var p struct {
			Token string `json:"token"`
			Q     string `json:"q"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		out, err := s.service.ListEntityTypes(ctx, p.Q, 500)
		if err != nil {
			return internalError(req.ID, err)
		}
		return response{JSONRPC: "2.0", Result: out, ID: req.ID}
	case "types.entity.create":
		identity, rpcResp, ok := s.authz(ctx, req, "graph.write")
		if !ok {
			return rpcResp
		}
		var p struct {
			Token       string `json:"token"`
			Key         string `json:"key"`
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		out, err := s.service.CreateEntityType(ctx, p.Key, p.Name, p.Description)
		if err != nil {
			return appError(req.ID, err)
		}
		s.service.WriteAudit(ctx, &identity.User.ID, "catalog.entity_type.create", "entity_type", &out.ID, "rpc")
		return response{JSONRPC: "2.0", Result: out, ID: req.ID}
	case "types.relation.list":
		_, rpcResp, ok := s.authz(ctx, req, "graph.read")
		if !ok {
			return rpcResp
		}
		var p struct {
			Token string `json:"token"`
			Q     string `json:"q"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		out, err := s.service.ListRelationTypes(ctx, p.Q, 500)
		if err != nil {
			return internalError(req.ID, err)
		}
		return response{JSONRPC: "2.0", Result: out, ID: req.ID}
	case "types.relation.create":
		identity, rpcResp, ok := s.authz(ctx, req, "graph.write")
		if !ok {
			return rpcResp
		}
		var p struct {
			Token       string `json:"token"`
			Key         string `json:"key"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Directed    bool   `json:"directed"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		out, err := s.service.CreateRelationType(ctx, p.Key, p.Name, p.Description, p.Directed)
		if err != nil {
			return appError(req.ID, err)
		}
		s.service.WriteAudit(ctx, &identity.User.ID, "catalog.relation_type.create", "relation_type", &out.ID, "rpc")
		return response{JSONRPC: "2.0", Result: out, ID: req.ID}
	case "types.attribute.list":
		_, rpcResp, ok := s.authz(ctx, req, "graph.read")
		if !ok {
			return rpcResp
		}
		var p struct {
			Token string `json:"token"`
			Scope string `json:"scope"`
			Q     string `json:"q"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		out, err := s.service.ListAttributeDefs(ctx, p.Scope, p.Q, 500)
		if err != nil {
			return internalError(req.ID, err)
		}
		return response{JSONRPC: "2.0", Result: out, ID: req.ID}
	case "types.attribute.upsert":
		identity, rpcResp, ok := s.authz(ctx, req, "graph.write")
		if !ok {
			return rpcResp
		}
		var p struct {
			Token       string `json:"token"`
			Scope       string `json:"scope"`
			Key         string `json:"key"`
			ValueKind   string `json:"value_kind"`
			Description string `json:"description"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		out, err := s.service.UpsertAttributeDef(ctx, p.Scope, p.Key, p.ValueKind, p.Description)
		if err != nil {
			return appError(req.ID, err)
		}
		s.service.WriteAudit(ctx, &identity.User.ID, "catalog.attribute_def.upsert", "attribute_def", &out.ID, "rpc")
		return response{JSONRPC: "2.0", Result: out, ID: req.ID}
	case "access.user.list":
		_, rpcResp, ok := s.authz(ctx, req, "graph.read")
		if !ok {
			return rpcResp
		}
		var p struct {
			Token string `json:"token"`
			Q     string `json:"q"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		out, err := s.service.ListUsers(ctx, p.Q, 500)
		if err != nil {
			return internalError(req.ID, err)
		}
		return response{JSONRPC: "2.0", Result: out, ID: req.ID}
	case "access.user.create":
		identity, rpcResp, ok := s.authz(ctx, req, "graph.write")
		if !ok {
			return rpcResp
		}
		var p struct {
			Token    string `json:"token"`
			Email    string `json:"email"`
			Password string `json:"password"`
			RoleID   uint   `json:"role_id"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		out, err := s.service.CreateUser(ctx, p.Email, p.Password, p.RoleID)
		if err != nil {
			return appError(req.ID, err)
		}
		s.service.WriteAudit(ctx, &identity.User.ID, "access.user.create", "user", &out.ID, "rpc")
		return response{JSONRPC: "2.0", Result: out, ID: req.ID}
	case "access.role.list":
		_, rpcResp, ok := s.authz(ctx, req, "graph.read")
		if !ok {
			return rpcResp
		}
		var p struct {
			Token string `json:"token"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		out, err := s.service.ListRoles(ctx)
		if err != nil {
			return internalError(req.ID, err)
		}
		return response{JSONRPC: "2.0", Result: out, ID: req.ID}
	case "access.role.assign":
		identity, rpcResp, ok := s.authz(ctx, req, "graph.write")
		if !ok {
			return rpcResp
		}
		var p struct {
			Token  string `json:"token"`
			UserID uint   `json:"user_id"`
			RoleID uint   `json:"role_id"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		if err := s.service.AssignRole(ctx, p.UserID, p.RoleID); err != nil {
			return appError(req.ID, err)
		}
		s.service.WriteAudit(ctx, &identity.User.ID, "access.role.assign", "user", &p.UserID, "rpc")
		return response{JSONRPC: "2.0", Result: map[string]any{"ok": true}, ID: req.ID}
	case "audit.list":
		_, rpcResp, ok := s.authz(ctx, req, "graph.read")
		if !ok {
			return rpcResp
		}
		var p struct {
			Token string `json:"token"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		out, err := s.service.ListAuditLogs(ctx, 500)
		if err != nil {
			return internalError(req.ID, err)
		}
		return response{JSONRPC: "2.0", Result: out, ID: req.ID}
	case "edges.connect":
		identity, rpcResp, ok := s.authz(ctx, req, "graph.write")
		if !ok {
			return rpcResp
		}
		var p struct {
			Token      string `json:"token"`
			From       uint   `json:"from"`
			RelationID uint   `json:"relation_id"`
			To         uint   `json:"to"`
			Directed   bool   `json:"directed"`
			State      string `json:"state"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		out, err := s.service.Connect(ctx, p.From, p.RelationID, p.To, p.Directed, p.State)
		if err != nil {
			return appError(req.ID, err)
		}
		s.service.WriteAudit(ctx, &identity.User.ID, "graph.edge.create", "edge", &out.ID, "rpc")
		return response{JSONRPC: "2.0", Result: out, ID: req.ID}
	case "edges.cut":
		identity, rpcResp, ok := s.authz(ctx, req, "graph.write")
		if !ok {
			return rpcResp
		}
		var p struct {
			Token  string `json:"token"`
			EdgeID uint   `json:"edge_id"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		out, err := s.service.CutEdge(ctx, p.EdgeID)
		if err != nil {
			return appError(req.ID, err)
		}
		s.service.WriteAudit(ctx, &identity.User.ID, "graph.edge.cut", "edge", &out.ID, "rpc")
		return response{JSONRPC: "2.0", Result: out, ID: req.ID}
	case "trace.run":
		_, rpcResp, ok := s.authz(ctx, req, "graph.read")
		if !ok {
			return rpcResp
		}
		var p struct {
			Token          string `json:"token"`
			StartEntityID  uint   `json:"start_entity_id"`
			TargetEntityID *uint  `json:"target_entity_id"`
			MaxDepth       int    `json:"max_depth"`
			RelationKeys   string `json:"relation_keys"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		out, err := s.service.Trace(ctx, domain.TraceQuery{
			StartEntityID:  p.StartEntityID,
			TargetEntityID: p.TargetEntityID,
			MaxDepth:       p.MaxDepth,
			RelationKeys:   splitCSV(p.RelationKeys),
		})
		if err != nil {
			return appError(req.ID, err)
		}
		return response{JSONRPC: "2.0", Result: out, ID: req.ID}
	case "workflow.chain.provision":
		identity, rpcResp, ok := s.authz(ctx, req, "graph.write")
		if !ok {
			return rpcResp
		}
		var p struct {
			Token     string `json:"token"`
			Nodes     string `json:"nodes"`
			Relations string `json:"relations"`
			Attrs     string `json:"attrs"`
			State     string `json:"state"`
		}
		if !decodeParams(req.Params, &p) {
			return invalidParams(req.ID)
		}
		nodes, err := parseRPCChainNodes(p.Nodes)
		if err != nil {
			return appError(req.ID, err)
		}
		rels, err := parseRPCChainRelations(p.Relations)
		if err != nil {
			return appError(req.ID, err)
		}
		out, err := s.service.ProvisionChain(ctx, application.ProvisionChainInput{
			Nodes:      nodes,
			Edges:      rels,
			Attributes: parseRPCEntityAttrs(p.Attrs),
			State:      p.State,
		})
		if err != nil {
			return appError(req.ID, err)
		}
		var targetID *uint
		if len(out.EntityIDs) > 0 {
			targetID = &out.EntityIDs[0]
		}
		s.service.WriteAudit(ctx, &identity.User.ID, "workflow.provision.chain", "entity", targetID, "rpc")
		return response{JSONRPC: "2.0", Result: out, ID: req.ID}
	default:
		return response{JSONRPC: "2.0", Error: &rpcError{Code: -32601, Message: "method not found"}, ID: req.ID}
	}
}

func (s *Server) handleAuthLogin(ctx context.Context, req request) response {
	var p struct {
		Email     string `json:"email"`
		Password  string `json:"password"`
		TokenName string `json:"token_name"`
	}
	if !decodeParams(req.Params, &p) {
		return invalidParams(req.ID)
	}
	u, token, err := s.service.LoginWithAPIToken(ctx, p.Email, p.Password, p.TokenName, nil)
	if err != nil {
		return response{JSONRPC: "2.0", Error: &rpcError{Code: 40100, Message: "invalid credentials"}, ID: req.ID}
	}
	return response{JSONRPC: "2.0", Result: map[string]any{"user_id": u.ID, "email": u.Email, "token": token}, ID: req.ID}
}

func (s *Server) authz(ctx context.Context, req request, permission string) (domain.Identity, response, bool) {
	var p struct {
		Token string `json:"token"`
	}
	if !decodeParams(req.Params, &p) {
		return domain.Identity{}, invalidParams(req.ID), false
	}
	identity, err := s.service.AuthenticateBearerToken(ctx, p.Token)
	if err != nil {
		return domain.Identity{}, response{JSONRPC: "2.0", Error: &rpcError{Code: 40100, Message: "unauthorized"}, ID: req.ID}, false
	}
	if permission != "" && !s.service.Can(identity, permission) {
		return domain.Identity{}, response{JSONRPC: "2.0", Error: &rpcError{Code: 40300, Message: "forbidden"}, ID: req.ID}, false
	}
	return identity, response{}, true
}

func decodeParams(raw json.RawMessage, out any) bool {
	if len(raw) == 0 {
		return false
	}
	return json.Unmarshal(raw, out) == nil
}

func splitCSV(input string) []string {
	parts := strings.Split(input, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}

func parseRPCChainNodes(input string) ([]application.ProvisionChainNode, error) {
	parts := strings.Split(input, ",")
	nodes := make([]application.ProvisionChainNode, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		kv := strings.SplitN(trimmed, ":", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("nodes format must be type_key:Entity Name,type_key:Entity Name")
		}
		nodes = append(nodes, application.ProvisionChainNode{TypeKey: strings.TrimSpace(kv[0]), EntityName: strings.TrimSpace(kv[1])})
	}
	if len(nodes) < 2 {
		return nil, fmt.Errorf("at least two nodes are required")
	}
	return nodes, nil
}

func parseRPCChainRelations(input string) ([]application.ProvisionChainEdge, error) {
	parts := strings.Split(input, ",")
	rels := make([]application.ProvisionChainEdge, 0, len(parts))
	for _, part := range parts {
		key := strings.TrimSpace(part)
		if key == "" {
			continue
		}
		rels = append(rels, application.ProvisionChainEdge{RelationKey: key})
	}
	if len(rels) == 0 {
		return nil, fmt.Errorf("at least one relation is required")
	}
	return rels, nil
}

func parseRPCEntityAttrs(input string) map[string]map[string]string {
	out := make(map[string]map[string]string)
	groups := strings.Split(input, ";")
	for _, group := range groups {
		g := strings.TrimSpace(group)
		if g == "" {
			continue
		}
		parts := strings.SplitN(g, ":", 2)
		if len(parts) != 2 {
			continue
		}
		entityName := strings.TrimSpace(parts[0])
		if entityName == "" {
			continue
		}
		if _, ok := out[entityName]; !ok {
			out[entityName] = make(map[string]string)
		}
		pairs := strings.Split(parts[1], ",")
		for _, pair := range pairs {
			kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.TrimSpace(kv[0])
			value := strings.TrimSpace(kv[1])
			if key == "" || value == "" {
				continue
			}
			out[entityName][key] = value
		}
	}
	return out
}

func invalidParams(id any) response {
	return response{JSONRPC: "2.0", Error: &rpcError{Code: -32602, Message: "invalid params"}, ID: id}
}

func appError(id any, err error) response {
	return response{JSONRPC: "2.0", Error: &rpcError{Code: 40000, Message: err.Error()}, ID: id}
}

func internalError(id any, err error) response {
	return response{JSONRPC: "2.0", Error: &rpcError{Code: 50000, Message: fmt.Sprintf("internal error: %v", err)}, ID: id}
}
