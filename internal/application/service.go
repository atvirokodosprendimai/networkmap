package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/atvirokodosprendimai/networkmap/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

type GraphService struct {
	repo domain.GraphRepository
}

type ProvisionChainNode struct {
	TypeKey    string `json:"type_key"`
	TypeName   string `json:"type_name"`
	EntityName string `json:"entity_name"`
}

type ProvisionChainEdge struct {
	RelationKey  string `json:"relation_key"`
	RelationName string `json:"relation_name"`
	Directed     bool   `json:"directed"`
}

type ProvisionChainInput struct {
	Nodes      []ProvisionChainNode         `json:"nodes"`
	Edges      []ProvisionChainEdge         `json:"edges"`
	Attributes map[string]map[string]string `json:"attributes"`
	State      string                       `json:"state"`
}

type ProvisionChainResult struct {
	EntityIDs []uint `json:"entity_ids"`
	EdgeIDs   []uint `json:"edge_ids"`
}

func NewGraphService(repo domain.GraphRepository) *GraphService {
	return &GraphService{repo: repo}
}

func (s *GraphService) CreateEntityType(ctx context.Context, key, name, description string) (domain.EntityType, error) {
	if key == "" || name == "" {
		return domain.EntityType{}, errors.New("key and name are required")
	}

	return s.repo.CreateEntityType(ctx, domain.EntityType{
		Key:         key,
		Name:        name,
		Description: description,
	})
}

func (s *GraphService) ListEntityTypes(ctx context.Context, query string, limit int) ([]domain.EntityType, error) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}
	return s.repo.ListEntityTypes(ctx, query, limit)
}

func (s *GraphService) CreateRelationType(ctx context.Context, key, name, description string, directed bool) (domain.RelationType, error) {
	if key == "" || name == "" {
		return domain.RelationType{}, errors.New("key and name are required")
	}

	return s.repo.CreateRelationType(ctx, domain.RelationType{
		Key:         key,
		Name:        name,
		Description: description,
		Directed:    directed,
	})
}

func (s *GraphService) ListRelationTypes(ctx context.Context, query string, limit int) ([]domain.RelationType, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	return s.repo.ListRelationTypes(ctx, query, limit)
}

func (s *GraphService) CreateEntity(ctx context.Context, entityTypeID uint, name, status string) (domain.Entity, error) {
	if entityTypeID == 0 || name == "" {
		return domain.Entity{}, errors.New("entity_type_id and name are required")
	}

	return s.repo.CreateEntity(ctx, domain.Entity{
		EntityTypeID: entityTypeID,
		Name:         name,
		Status:       status,
	})
}

func (s *GraphService) ListEntities(ctx context.Context, entityTypeID *uint, query string, limit int) ([]domain.Entity, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	return s.repo.ListEntities(ctx, entityTypeID, query, limit)
}

func (s *GraphService) ListEdges(ctx context.Context, limit int) ([]domain.EdgeSummary, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	return s.repo.ListEdges(ctx, limit)
}

func (s *GraphService) Connect(ctx context.Context, subjectID, relationTypeID, objectID uint, directed bool, state string) (domain.EdgeTriple, error) {
	if subjectID == 0 || relationTypeID == 0 || objectID == 0 {
		return domain.EdgeTriple{}, errors.New("subject, relation_type and object ids are required")
	}

	return s.repo.CreateEdge(ctx, domain.EdgeTriple{
		SubjectEntityID: subjectID,
		RelationTypeID:  relationTypeID,
		ObjectEntityID:  objectID,
		Directed:        directed,
		State:           state,
	})
}

func (s *GraphService) UpsertAttributeDef(ctx context.Context, scope, key, valueKind, description string) (domain.AttributeDef, error) {
	if scope == "" || key == "" {
		return domain.AttributeDef{}, errors.New("scope and key are required")
	}

	return s.repo.UpsertAttributeDef(ctx, domain.AttributeDef{
		Scope:       scope,
		Key:         key,
		ValueKind:   valueKind,
		Description: description,
	})
}

func (s *GraphService) ListAttributeDefs(ctx context.Context, scope, query string, limit int) ([]domain.AttributeDef, error) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}
	return s.repo.ListAttributeDefs(ctx, scope, query, limit)
}

func (s *GraphService) SetEntityAttribute(ctx context.Context, entityID, attrDefID uint, value string) (domain.EntityAttribute, error) {
	if entityID == 0 || attrDefID == 0 {
		return domain.EntityAttribute{}, errors.New("entity_id and attribute_def_id are required")
	}

	return s.repo.UpsertEntityAttribute(ctx, domain.EntityAttribute{
		EntityID:       entityID,
		AttributeDefID: attrDefID,
		Value:          value,
	})
}

func (s *GraphService) SetEdgeAttribute(ctx context.Context, edgeID, attrDefID uint, value string) (domain.EdgeAttribute, error) {
	if edgeID == 0 || attrDefID == 0 {
		return domain.EdgeAttribute{}, errors.New("edge_id and attribute_def_id are required")
	}

	return s.repo.UpsertEdgeAttribute(ctx, domain.EdgeAttribute{
		EdgeID:         edgeID,
		AttributeDefID: attrDefID,
		Value:          value,
	})
}

func (s *GraphService) CutEdge(ctx context.Context, edgeID uint) (domain.EdgeTriple, error) {
	if edgeID == 0 {
		return domain.EdgeTriple{}, errors.New("edge_id is required")
	}

	return s.repo.UpdateEdgeState(ctx, edgeID, "cut")
}

func (s *GraphService) GetEdgeByID(ctx context.Context, edgeID uint) (domain.EdgeSummary, error) {
	if edgeID == 0 {
		return domain.EdgeSummary{}, errors.New("edge_id is required")
	}
	return s.repo.GetEdgeByID(ctx, edgeID)
}

func (s *GraphService) Trace(ctx context.Context, query domain.TraceQuery) ([]domain.TraversalHop, error) {
	if query.StartEntityID == 0 {
		return nil, errors.New("start_entity_id is required")
	}
	if query.MaxDepth <= 0 {
		query.MaxDepth = 8
	}

	return s.repo.Trace(ctx, query)
}

func (s *GraphService) BootstrapAdmin(ctx context.Context, email, password string) error {
	if strings.TrimSpace(email) == "" || strings.TrimSpace(password) == "" {
		return errors.New("bootstrap admin email and password are required")
	}

	count, err := s.repo.CountUsers(ctx)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	hash, err := hashPassword(password)
	if err != nil {
		return err
	}

	u, err := s.repo.CreateUser(ctx, domain.User{Email: strings.ToLower(strings.TrimSpace(email)), PasswordHash: hash})
	if err != nil {
		return err
	}

	adminRoleID, err := s.repo.CreateRoleIfMissing(ctx, "admin", "Administrator")
	if err != nil {
		return err
	}
	permID, err := s.repo.CreatePermissionIfMissing(ctx, "*")
	if err != nil {
		return err
	}
	if err := s.repo.GrantPermissionToRole(ctx, adminRoleID, permID); err != nil {
		return err
	}
	if err := s.repo.AssignRoleToUser(ctx, u.ID, adminRoleID); err != nil {
		return err
	}

	return s.repo.CreateAuditLog(ctx, domain.AuditLog{ActorUserID: &u.ID, Action: "auth.bootstrap_admin", TargetType: "user", TargetID: &u.ID, Metadata: "initial admin created"})
}

func (s *GraphService) LoginWithSession(ctx context.Context, email, password string, ttl time.Duration) (domain.User, string, error) {
	u, err := s.authenticateEmailPassword(ctx, email, password)
	if err != nil {
		return domain.User{}, "", err
	}

	plain, hash, err := newTokenPair()
	if err != nil {
		return domain.User{}, "", err
	}

	_, err = s.repo.CreateSession(ctx, domain.AuthSession{
		UserID:    u.ID,
		TokenHash: hash,
		ExpiresAt: time.Now().UTC().Add(ttl),
	})
	if err != nil {
		return domain.User{}, "", err
	}

	_ = s.repo.CreateAuditLog(ctx, domain.AuditLog{ActorUserID: &u.ID, Action: "auth.login.session", TargetType: "user", TargetID: &u.ID, Metadata: "session login"})
	return u, plain, nil
}

func (s *GraphService) LoginWithAPIToken(ctx context.Context, email, password, tokenName string, ttl *time.Duration) (domain.User, string, error) {
	u, err := s.authenticateEmailPassword(ctx, email, password)
	if err != nil {
		return domain.User{}, "", err
	}

	plain, hash, err := newTokenPair()
	if err != nil {
		return domain.User{}, "", err
	}

	var expiresAt *time.Time
	if ttl != nil {
		t := time.Now().UTC().Add(*ttl)
		expiresAt = &t
	}

	_, err = s.repo.CreateAPIToken(ctx, domain.APIToken{
		UserID:    u.ID,
		Name:      defaultString(tokenName, "cli"),
		TokenHash: hash,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return domain.User{}, "", err
	}

	_ = s.repo.CreateAuditLog(ctx, domain.AuditLog{ActorUserID: &u.ID, Action: "auth.login.api_token", TargetType: "user", TargetID: &u.ID, Metadata: "api token issued"})
	return u, plain, nil
}

func (s *GraphService) AuthenticateSession(ctx context.Context, token string) (domain.Identity, error) {
	hash := hashToken(token)
	session, err := s.repo.GetSessionByTokenHash(ctx, hash)
	if err != nil {
		return domain.Identity{}, errors.New("unauthorized")
	}
	if session.ExpiresAt.Before(time.Now().UTC()) {
		_ = s.repo.DeleteSessionByTokenHash(ctx, hash)
		return domain.Identity{}, errors.New("session expired")
	}

	return s.identityByUserID(ctx, session.UserID)
}

func (s *GraphService) AuthenticateBearerToken(ctx context.Context, token string) (domain.Identity, error) {
	hash := hashToken(token)
	apit, err := s.repo.GetAPITokenByTokenHash(ctx, hash)
	if err != nil {
		return domain.Identity{}, errors.New("unauthorized")
	}
	if apit.ExpiresAt != nil && apit.ExpiresAt.Before(time.Now().UTC()) {
		return domain.Identity{}, errors.New("token expired")
	}

	return s.identityByUserID(ctx, apit.UserID)
}

func (s *GraphService) LogoutSession(ctx context.Context, token string) error {
	if strings.TrimSpace(token) == "" {
		return nil
	}
	return s.repo.DeleteSessionByTokenHash(ctx, hashToken(token))
}

func (s *GraphService) Can(identity domain.Identity, permission string) bool {
	if _, ok := identity.Permissions["*"]; ok {
		return true
	}
	_, ok := identity.Permissions[permission]
	return ok
}

func (s *GraphService) WriteAudit(ctx context.Context, actorUserID *uint, action, targetType string, targetID *uint, metadata string) {
	_ = s.repo.CreateAuditLog(ctx, domain.AuditLog{
		ActorUserID: actorUserID,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		Metadata:    metadata,
	})
}

func (s *GraphService) SaveTraceRun(ctx context.Context, actorUserID *uint, query domain.TraceQuery, hopCount int) error {
	_, err := s.repo.CreateTraceRun(ctx, domain.TraceRun{
		ActorUserID:    actorUserID,
		StartEntityID:  query.StartEntityID,
		TargetEntityID: query.TargetEntityID,
		MaxDepth:       query.MaxDepth,
		RelationKeys:   strings.Join(query.RelationKeys, ","),
		HopCount:       hopCount,
	})
	return err
}

func (s *GraphService) ListTraceRuns(ctx context.Context, actorUserID *uint, limit int) ([]domain.TraceRun, error) {
	if limit <= 0 {
		limit = 30
	}
	return s.repo.ListTraceRuns(ctx, actorUserID, limit)
}

func (s *GraphService) CreateUser(ctx context.Context, email, password string, roleID uint) (domain.User, error) {
	if strings.TrimSpace(email) == "" || strings.TrimSpace(password) == "" {
		return domain.User{}, errors.New("email and password are required")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return domain.User{}, err
	}
	u, err := s.repo.CreateUser(ctx, domain.User{Email: strings.ToLower(strings.TrimSpace(email)), PasswordHash: hash})
	if err != nil {
		return domain.User{}, err
	}
	if roleID != 0 {
		if err := s.repo.AssignRoleToUser(ctx, u.ID, roleID); err != nil {
			return domain.User{}, err
		}
	}
	return u, nil
}

func (s *GraphService) ListUsers(ctx context.Context, query string, limit int) ([]domain.User, error) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}
	return s.repo.ListUsers(ctx, query, limit)
}

func (s *GraphService) ListRoles(ctx context.Context) ([]domain.Role, error) {
	return s.repo.ListRoles(ctx)
}

func (s *GraphService) AssignRole(ctx context.Context, userID, roleID uint) error {
	if userID == 0 || roleID == 0 {
		return errors.New("user_id and role_id are required")
	}
	return s.repo.AssignRoleToUser(ctx, userID, roleID)
}

func (s *GraphService) ListAuditLogs(ctx context.Context, limit int) ([]domain.AuditRecord, error) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}
	return s.repo.ListAuditLogs(ctx, limit)
}

func (s *GraphService) ProvisionChain(ctx context.Context, in ProvisionChainInput) (ProvisionChainResult, error) {
	if len(in.Nodes) < 2 {
		return ProvisionChainResult{}, errors.New("at least two nodes are required")
	}
	if len(in.Edges) != len(in.Nodes)-1 {
		return ProvisionChainResult{}, errors.New("edges count must be nodes count minus one")
	}
	state := strings.TrimSpace(in.State)
	if state == "" {
		state = "active"
	}

	entityIDs := make([]uint, 0, len(in.Nodes))
	edgeIDs := make([]uint, 0, len(in.Edges))
	entityNameToID := make(map[string]uint, len(in.Nodes))

	for _, node := range in.Nodes {
		typeKey := strings.TrimSpace(node.TypeKey)
		entityName := strings.TrimSpace(node.EntityName)
		if typeKey == "" || entityName == "" {
			return ProvisionChainResult{}, errors.New("every node must include type_key and entity_name")
		}
		typeName := strings.TrimSpace(node.TypeName)
		if typeName == "" {
			typeName = strings.ReplaceAll(typeKey, "_", " ")
		}
		entityType, err := s.ensureEntityTypeByKey(ctx, typeKey, typeName, "Auto-created by chain provisioning")
		if err != nil {
			return ProvisionChainResult{}, err
		}
		entity, err := s.ensureEntityByNameAndType(ctx, entityType.ID, entityName, state)
		if err != nil {
			return ProvisionChainResult{}, err
		}
		entityIDs = append(entityIDs, entity.ID)
		entityNameToID[entityName] = entity.ID
	}

	for idx, edge := range in.Edges {
		relKey := strings.TrimSpace(edge.RelationKey)
		if relKey == "" {
			return ProvisionChainResult{}, errors.New("every edge must include relation_key")
		}
		relName := strings.TrimSpace(edge.RelationName)
		if relName == "" {
			relName = strings.ReplaceAll(relKey, "_", " ")
		}
		relation, err := s.ensureRelationTypeByKey(ctx, relKey, relName, "Auto-created by chain provisioning", edge.Directed)
		if err != nil {
			return ProvisionChainResult{}, err
		}
		created, err := s.ensureEdgeByTriple(ctx, entityIDs[idx], relation.ID, entityIDs[idx+1], edge.Directed, state)
		if err != nil {
			return ProvisionChainResult{}, err
		}
		edgeIDs = append(edgeIDs, created.ID)
	}

	for entityName, attrs := range in.Attributes {
		entityID, ok := entityNameToID[entityName]
		if !ok {
			continue
		}
		for key, value := range attrs {
			attrKey := strings.TrimSpace(key)
			attrValue := strings.TrimSpace(value)
			if attrKey == "" || attrValue == "" {
				continue
			}
			attrDef, err := s.ensureAttributeDefByKey(ctx, "entity", attrKey, "string", "Auto-created by chain provisioning")
			if err != nil {
				continue
			}
			_, _ = s.SetEntityAttribute(ctx, entityID, attrDef.ID, attrValue)
		}
	}

	return ProvisionChainResult{EntityIDs: entityIDs, EdgeIDs: edgeIDs}, nil
}

func (s *GraphService) ensureEntityTypeByKey(ctx context.Context, key, name, description string) (domain.EntityType, error) {
	items, err := s.ListEntityTypes(ctx, key, 50)
	if err != nil {
		return domain.EntityType{}, err
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Key), strings.TrimSpace(key)) {
			return item, nil
		}
	}
	return s.CreateEntityType(ctx, key, name, description)
}

func (s *GraphService) ensureRelationTypeByKey(ctx context.Context, key, name, description string, directed bool) (domain.RelationType, error) {
	items, err := s.ListRelationTypes(ctx, key, 50)
	if err != nil {
		return domain.RelationType{}, err
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Key), strings.TrimSpace(key)) {
			return item, nil
		}
	}
	return s.CreateRelationType(ctx, key, name, description, directed)
}

func (s *GraphService) ensureAttributeDefByKey(ctx context.Context, scope, key, valueKind, description string) (domain.AttributeDef, error) {
	items, err := s.ListAttributeDefs(ctx, scope, key, 200)
	if err != nil {
		return domain.AttributeDef{}, err
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Scope), strings.TrimSpace(scope)) && strings.EqualFold(strings.TrimSpace(item.Key), strings.TrimSpace(key)) {
			return item, nil
		}
	}
	return s.UpsertAttributeDef(ctx, scope, key, valueKind, description)
}

func (s *GraphService) ensureEntityByNameAndType(ctx context.Context, typeID uint, name, status string) (domain.Entity, error) {
	items, err := s.ListEntities(ctx, &typeID, name, 200)
	if err != nil {
		return domain.Entity{}, err
	}
	for _, item := range items {
		if item.EntityTypeID == typeID && strings.EqualFold(strings.TrimSpace(item.Name), strings.TrimSpace(name)) {
			return item, nil
		}
	}
	return s.CreateEntity(ctx, typeID, name, status)
}

func (s *GraphService) ensureEdgeByTriple(ctx context.Context, fromID, relationID, toID uint, directed bool, state string) (domain.EdgeTriple, error) {
	edges, err := s.ListEdges(ctx, 1000)
	if err != nil {
		return domain.EdgeTriple{}, err
	}
	for _, edge := range edges {
		if edge.SubjectEntityID == fromID && edge.RelationTypeID == relationID && edge.ObjectEntityID == toID {
			return domain.EdgeTriple{
				ID:              edge.ID,
				SubjectEntityID: edge.SubjectEntityID,
				RelationTypeID:  edge.RelationTypeID,
				ObjectEntityID:  edge.ObjectEntityID,
				Directed:        edge.Directed,
				State:           edge.State,
			}, nil
		}
	}
	return s.Connect(ctx, fromID, relationID, toID, directed, state)
}

func (s *GraphService) authenticateEmailPassword(ctx context.Context, email, password string) (domain.User, error) {
	u, err := s.repo.GetUserByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		return domain.User{}, errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return domain.User{}, errors.New("invalid credentials")
	}
	return u, nil
}

func (s *GraphService) identityByUserID(ctx context.Context, userID uint) (domain.Identity, error) {
	u, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return domain.Identity{}, errors.New("unauthorized")
	}
	permList, err := s.repo.GetPermissionsByUserID(ctx, userID)
	if err != nil {
		return domain.Identity{}, err
	}
	permMap := make(map[string]struct{}, len(permList))
	for _, p := range permList {
		permMap[p] = struct{}{}
	}
	return domain.Identity{User: u, Permissions: permMap}, nil
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func newTokenPair() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	plain := base64.RawURLEncoding.EncodeToString(raw)
	return plain, hashToken(plain), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum[:])
}

func defaultString(input, fallback string) string {
	if strings.TrimSpace(input) == "" {
		return fallback
	}
	return input
}
