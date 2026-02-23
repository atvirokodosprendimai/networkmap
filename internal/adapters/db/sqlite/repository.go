package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/atvirokodosprendimai/networkmap/internal/domain"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	_ "modernc.org/sqlite"
)

type GraphRepository struct {
	db *gorm.DB
}

func Open(path string) (*gorm.DB, error) {
	return gorm.Open(sqlite.Dialector{
		DriverName: "sqlite",
		DSN:        path,
	}, &gorm.Config{})
}

func NewGraphRepository(db *gorm.DB) *GraphRepository {
	return &GraphRepository{db: db}
}

func (r *GraphRepository) CreateEntityType(ctx context.Context, value domain.EntityType) (domain.EntityType, error) {
	m := EntityTypeModel{Key: value.Key, Name: value.Name, Description: value.Description}
	if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
		return domain.EntityType{}, err
	}

	return domain.EntityType{
		ID:          m.ID,
		Key:         m.Key,
		Name:        m.Name,
		Description: m.Description,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}, nil
}

func (r *GraphRepository) ListEntityTypes(ctx context.Context, query string, limit int) ([]domain.EntityType, error) {
	q := r.db.WithContext(ctx).Model(&EntityTypeModel{})
	if strings.TrimSpace(query) != "" {
		like := "%" + strings.TrimSpace(query) + "%"
		q = q.Where("name LIKE ? OR key LIKE ?", like, like)
	}
	rows := make([]EntityTypeModel, 0)
	if err := q.Order("id DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	result := make([]domain.EntityType, 0, len(rows))
	for _, m := range rows {
		result = append(result, domain.EntityType{ID: m.ID, Key: m.Key, Name: m.Name, Description: m.Description, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt})
	}
	return result, nil
}

func (r *GraphRepository) CreateRelationType(ctx context.Context, value domain.RelationType) (domain.RelationType, error) {
	m := RelationTypeModel{Key: value.Key, Name: value.Name, Description: value.Description, Directed: value.Directed}
	if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
		return domain.RelationType{}, err
	}

	return domain.RelationType{
		ID:          m.ID,
		Key:         m.Key,
		Name:        m.Name,
		Description: m.Description,
		Directed:    m.Directed,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}, nil
}

func (r *GraphRepository) ListRelationTypes(ctx context.Context, query string, limit int) ([]domain.RelationType, error) {
	q := r.db.WithContext(ctx).Model(&RelationTypeModel{})
	if strings.TrimSpace(query) != "" {
		like := "%" + strings.TrimSpace(query) + "%"
		q = q.Where("name LIKE ? OR key LIKE ?", like, like)
	}

	rows := make([]RelationTypeModel, 0)
	if err := q.Order("id DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}

	result := make([]domain.RelationType, 0, len(rows))
	for _, m := range rows {
		result = append(result, domain.RelationType{
			ID:          m.ID,
			Key:         m.Key,
			Name:        m.Name,
			Description: m.Description,
			Directed:    m.Directed,
			CreatedAt:   m.CreatedAt,
			UpdatedAt:   m.UpdatedAt,
		})
	}

	return result, nil
}

func (r *GraphRepository) CreateEntity(ctx context.Context, value domain.Entity) (domain.Entity, error) {
	m := EntityModel{EntityTypeID: value.EntityTypeID, Name: value.Name, Status: defaultString(value.Status, "active")}
	if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
		return domain.Entity{}, err
	}

	return domain.Entity{
		ID:           m.ID,
		EntityTypeID: m.EntityTypeID,
		Name:         m.Name,
		Status:       m.Status,
		CreatedAt:    m.CreatedAt,
		UpdatedAt:    m.UpdatedAt,
	}, nil
}

func (r *GraphRepository) ListEntities(ctx context.Context, entityTypeID *uint, query string, limit int) ([]domain.Entity, error) {
	q := r.db.WithContext(ctx).Model(&EntityModel{})
	if entityTypeID != nil {
		q = q.Where("entity_type_id = ?", *entityTypeID)
	}
	if strings.TrimSpace(query) != "" {
		like := "%" + strings.TrimSpace(query) + "%"
		q = q.Where("name LIKE ?", like)
	}

	rows := make([]EntityModel, 0)
	if err := q.Order("id DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}

	result := make([]domain.Entity, 0, len(rows))
	for _, m := range rows {
		result = append(result, domain.Entity{
			ID:           m.ID,
			EntityTypeID: m.EntityTypeID,
			Name:         m.Name,
			Status:       m.Status,
			CreatedAt:    m.CreatedAt,
			UpdatedAt:    m.UpdatedAt,
		})
	}

	return result, nil
}

func (r *GraphRepository) ListEdges(ctx context.Context, limit int) ([]domain.EdgeSummary, error) {
	type row struct {
		ID              uint
		SubjectEntityID uint
		SubjectName     string
		RelationTypeID  uint
		RelationKey     string
		ObjectEntityID  uint
		ObjectName      string
		Directed        bool
		State           string
		CreatedAt       time.Time
		UpdatedAt       time.Time
	}

	rows := make([]row, 0)
	if err := r.db.WithContext(ctx).Raw(`
SELECT e.id,
       e.subject_entity_id,
       se.name AS subject_name,
       e.relation_type_id,
       rt.key AS relation_key,
       e.object_entity_id,
       oe.name AS object_name,
       e.directed,
       e.state,
       e.created_at,
       e.updated_at
FROM edges e
LEFT JOIN entities se ON se.id = e.subject_entity_id
LEFT JOIN entities oe ON oe.id = e.object_entity_id
LEFT JOIN relation_types rt ON rt.id = e.relation_type_id
ORDER BY e.id DESC
LIMIT ?
`, limit).Scan(&rows).Error; err != nil {
		return nil, err
	}
	result := make([]domain.EdgeSummary, 0, len(rows))
	for _, m := range rows {
		result = append(result, domain.EdgeSummary{
			ID:              m.ID,
			SubjectEntityID: m.SubjectEntityID,
			SubjectName:     m.SubjectName,
			RelationTypeID:  m.RelationTypeID,
			RelationKey:     m.RelationKey,
			ObjectEntityID:  m.ObjectEntityID,
			ObjectName:      m.ObjectName,
			Directed:        m.Directed,
			State:           m.State,
			CreatedAt:       m.CreatedAt,
			UpdatedAt:       m.UpdatedAt,
		})
	}
	return result, nil
}

func (r *GraphRepository) CreateEdge(ctx context.Context, value domain.EdgeTriple) (domain.EdgeTriple, error) {
	m := EdgeModel{
		SubjectEntityID: value.SubjectEntityID,
		RelationTypeID:  value.RelationTypeID,
		ObjectEntityID:  value.ObjectEntityID,
		Directed:        value.Directed,
		State:           defaultString(value.State, "active"),
	}
	if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
		return domain.EdgeTriple{}, err
	}

	return domain.EdgeTriple{
		ID:              m.ID,
		SubjectEntityID: m.SubjectEntityID,
		RelationTypeID:  m.RelationTypeID,
		ObjectEntityID:  m.ObjectEntityID,
		Directed:        m.Directed,
		State:           m.State,
		CreatedAt:       m.CreatedAt,
		UpdatedAt:       m.UpdatedAt,
	}, nil
}

func (r *GraphRepository) GetEdgeByID(ctx context.Context, edgeID uint) (domain.EdgeSummary, error) {
	type row struct {
		ID              uint
		SubjectEntityID uint
		SubjectName     string
		RelationTypeID  uint
		RelationKey     string
		ObjectEntityID  uint
		ObjectName      string
		Directed        bool
		State           string
		CreatedAt       time.Time
		UpdatedAt       time.Time
	}

	var m row
	if err := r.db.WithContext(ctx).Raw(`
SELECT e.id,
       e.subject_entity_id,
       se.name AS subject_name,
       e.relation_type_id,
       rt.key AS relation_key,
       e.object_entity_id,
       oe.name AS object_name,
       e.directed,
       e.state,
       e.created_at,
       e.updated_at
FROM edges e
LEFT JOIN entities se ON se.id = e.subject_entity_id
LEFT JOIN entities oe ON oe.id = e.object_entity_id
LEFT JOIN relation_types rt ON rt.id = e.relation_type_id
WHERE e.id = ?
`, edgeID).Scan(&m).Error; err != nil {
		return domain.EdgeSummary{}, err
	}
	if m.ID == 0 {
		return domain.EdgeSummary{}, gorm.ErrRecordNotFound
	}
	return domain.EdgeSummary{
		ID:              m.ID,
		SubjectEntityID: m.SubjectEntityID,
		SubjectName:     m.SubjectName,
		RelationTypeID:  m.RelationTypeID,
		RelationKey:     m.RelationKey,
		ObjectEntityID:  m.ObjectEntityID,
		ObjectName:      m.ObjectName,
		Directed:        m.Directed,
		State:           m.State,
		CreatedAt:       m.CreatedAt,
		UpdatedAt:       m.UpdatedAt,
	}, nil
}

func (r *GraphRepository) UpdateEdgeState(ctx context.Context, edgeID uint, state string) (domain.EdgeTriple, error) {
	if err := r.db.WithContext(ctx).Model(&EdgeModel{}).Where("id = ?", edgeID).Update("state", state).Error; err != nil {
		return domain.EdgeTriple{}, err
	}
	var m EdgeModel
	if err := r.db.WithContext(ctx).First(&m, edgeID).Error; err != nil {
		return domain.EdgeTriple{}, err
	}

	return domain.EdgeTriple{
		ID:              m.ID,
		SubjectEntityID: m.SubjectEntityID,
		RelationTypeID:  m.RelationTypeID,
		ObjectEntityID:  m.ObjectEntityID,
		Directed:        m.Directed,
		State:           m.State,
		CreatedAt:       m.CreatedAt,
		UpdatedAt:       m.UpdatedAt,
	}, nil
}

func (r *GraphRepository) UpsertAttributeDef(ctx context.Context, value domain.AttributeDef) (domain.AttributeDef, error) {
	m := AttributeDefModel{Scope: value.Scope, Key: value.Key, ValueKind: defaultString(value.ValueKind, "string"), Description: value.Description}
	err := r.db.WithContext(ctx).
		Where("scope = ? AND key = ?", value.Scope, value.Key).
		Assign(map[string]any{"value_kind": m.ValueKind, "description": value.Description}).
		FirstOrCreate(&m).Error
	if err != nil {
		return domain.AttributeDef{}, err
	}

	return domain.AttributeDef{
		ID:          m.ID,
		Scope:       m.Scope,
		Key:         m.Key,
		ValueKind:   m.ValueKind,
		Description: m.Description,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}, nil
}

func (r *GraphRepository) ListAttributeDefs(ctx context.Context, scope, query string, limit int) ([]domain.AttributeDef, error) {
	q := r.db.WithContext(ctx).Model(&AttributeDefModel{})
	if strings.TrimSpace(scope) != "" {
		q = q.Where("scope = ?", strings.TrimSpace(scope))
	}
	if strings.TrimSpace(query) != "" {
		like := "%" + strings.TrimSpace(query) + "%"
		q = q.Where("key LIKE ?", like)
	}
	rows := make([]AttributeDefModel, 0)
	if err := q.Order("id DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	result := make([]domain.AttributeDef, 0, len(rows))
	for _, m := range rows {
		result = append(result, domain.AttributeDef{ID: m.ID, Scope: m.Scope, Key: m.Key, ValueKind: m.ValueKind, Description: m.Description, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt})
	}
	return result, nil
}

func (r *GraphRepository) UpsertEntityAttribute(ctx context.Context, value domain.EntityAttribute) (domain.EntityAttribute, error) {
	m := EntityAttributeModel{EntityID: value.EntityID, AttributeDefID: value.AttributeDefID, Value: value.Value}
	err := r.db.WithContext(ctx).
		Where("entity_id = ? AND attribute_def_id = ?", value.EntityID, value.AttributeDefID).
		Assign(map[string]any{"value": value.Value}).
		FirstOrCreate(&m).Error
	if err != nil {
		return domain.EntityAttribute{}, err
	}

	return domain.EntityAttribute{
		ID:             m.ID,
		EntityID:       m.EntityID,
		AttributeDefID: m.AttributeDefID,
		Value:          m.Value,
		CreatedAt:      m.CreatedAt,
		UpdatedAt:      m.UpdatedAt,
	}, nil
}

func (r *GraphRepository) UpsertEdgeAttribute(ctx context.Context, value domain.EdgeAttribute) (domain.EdgeAttribute, error) {
	m := EdgeAttributeModel{EdgeID: value.EdgeID, AttributeDefID: value.AttributeDefID, Value: value.Value}
	err := r.db.WithContext(ctx).
		Where("edge_id = ? AND attribute_def_id = ?", value.EdgeID, value.AttributeDefID).
		Assign(map[string]any{"value": value.Value}).
		FirstOrCreate(&m).Error
	if err != nil {
		return domain.EdgeAttribute{}, err
	}

	return domain.EdgeAttribute{
		ID:             m.ID,
		EdgeID:         m.EdgeID,
		AttributeDefID: m.AttributeDefID,
		Value:          m.Value,
		CreatedAt:      m.CreatedAt,
		UpdatedAt:      m.UpdatedAt,
	}, nil
}

type traceRow struct {
	Depth          int
	FromEntityID   uint
	FromEntityName string
	EdgeID         uint
	RelationTypeID uint
	RelationKey    string
	ToEntityID     uint
	ToEntityName   string
	Path           string
}

func (r *GraphRepository) Trace(ctx context.Context, query domain.TraceQuery) ([]domain.TraversalHop, error) {
	relationClause := ""
	args := []any{query.StartEntityID, query.StartEntityID, query.StartEntityID, query.StartEntityID, query.MaxDepth}

	if len(query.RelationKeys) > 0 {
		placeholders := make([]string, 0, len(query.RelationKeys))
		for _, key := range query.RelationKeys {
			placeholders = append(placeholders, "?")
			args = append(args, key)
		}
		relationClause = " AND rt.key IN (" + strings.Join(placeholders, ",") + ")"
	}

	targetClause := ""
	if query.TargetEntityID != nil {
		targetClause = "WHERE walk.to_entity_id = ?"
		args = append(args, *query.TargetEntityID)
	}

	q := fmt.Sprintf(`
WITH RECURSIVE walk(depth, current_entity_id, from_entity_id, edge_id, relation_type_id, to_entity_id, path) AS (
    SELECT
        0 AS depth,
        ? AS current_entity_id,
        ? AS from_entity_id,
        0 AS edge_id,
        0 AS relation_type_id,
        ? AS to_entity_id,
        ',' || CAST(? AS TEXT) || ',' AS path
    UNION ALL
    SELECT
        walk.depth + 1,
        CASE
            WHEN e.subject_entity_id = walk.current_entity_id THEN e.object_entity_id
            ELSE e.subject_entity_id
        END AS current_entity_id,
        walk.current_entity_id AS from_entity_id,
        e.id AS edge_id,
        e.relation_type_id AS relation_type_id,
        CASE
            WHEN e.subject_entity_id = walk.current_entity_id THEN e.object_entity_id
            ELSE e.subject_entity_id
        END AS to_entity_id,
        walk.path || CAST(CASE
            WHEN e.subject_entity_id = walk.current_entity_id THEN e.object_entity_id
            ELSE e.subject_entity_id
        END AS TEXT) || ',' AS path
    FROM walk
    JOIN edges e
      ON (
         e.subject_entity_id = walk.current_entity_id
         OR (e.directed = 0 AND e.object_entity_id = walk.current_entity_id)
      )
    JOIN relation_types rt ON rt.id = e.relation_type_id
    WHERE walk.depth < ?
      AND e.state = 'active'%s
      AND instr(
        walk.path,
        ',' || CAST(CASE
            WHEN e.subject_entity_id = walk.current_entity_id THEN e.object_entity_id
            ELSE e.subject_entity_id
        END AS TEXT) || ','
      ) = 0
)
SELECT
    walk.depth,
    walk.from_entity_id,
    fe.name AS from_entity_name,
    walk.edge_id,
    walk.relation_type_id,
    rt.key AS relation_key,
    walk.to_entity_id,
    te.name AS to_entity_name,
    walk.path
FROM walk
LEFT JOIN entities fe ON fe.id = walk.from_entity_id
LEFT JOIN entities te ON te.id = walk.to_entity_id
LEFT JOIN relation_types rt ON rt.id = walk.relation_type_id
%s
ORDER BY walk.depth ASC;
`, relationClause, targetClause)

	rows := make([]traceRow, 0)
	if err := r.db.WithContext(ctx).Raw(q, args...).Scan(&rows).Error; err != nil {
		return nil, err
	}

	result := make([]domain.TraversalHop, 0, len(rows))
	for _, row := range rows {
		if row.EdgeID == 0 {
			continue
		}

		result = append(result, domain.TraversalHop{
			Depth:          row.Depth,
			FromEntityID:   row.FromEntityID,
			FromEntityName: row.FromEntityName,
			EdgeID:         row.EdgeID,
			RelationTypeID: row.RelationTypeID,
			RelationKey:    row.RelationKey,
			ToEntityID:     row.ToEntityID,
			ToEntityName:   row.ToEntityName,
			Path:           row.Path,
		})
	}

	return result, nil
}

func defaultString(input, fallback string) string {
	if strings.TrimSpace(input) == "" {
		return fallback
	}

	return input
}

func (r *GraphRepository) CreateUser(ctx context.Context, value domain.User) (domain.User, error) {
	m := UserModel{Email: strings.ToLower(strings.TrimSpace(value.Email)), PasswordHash: value.PasswordHash}
	if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
		return domain.User{}, err
	}
	return domain.User{ID: m.ID, Email: m.Email, PasswordHash: m.PasswordHash, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt}, nil
}

func (r *GraphRepository) CountUsers(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&UserModel{}).Count(&count).Error
	return count, err
}

func (r *GraphRepository) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	var m UserModel
	if err := r.db.WithContext(ctx).Where("email = ?", strings.ToLower(strings.TrimSpace(email))).First(&m).Error; err != nil {
		return domain.User{}, err
	}
	return domain.User{ID: m.ID, Email: m.Email, PasswordHash: m.PasswordHash, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt}, nil
}

func (r *GraphRepository) GetUserByID(ctx context.Context, id uint) (domain.User, error) {
	var m UserModel
	if err := r.db.WithContext(ctx).First(&m, id).Error; err != nil {
		return domain.User{}, err
	}
	return domain.User{ID: m.ID, Email: m.Email, PasswordHash: m.PasswordHash, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt}, nil
}

func (r *GraphRepository) CreateSession(ctx context.Context, value domain.AuthSession) (domain.AuthSession, error) {
	m := SessionModel{UserID: value.UserID, TokenHash: value.TokenHash, ExpiresAt: value.ExpiresAt}
	if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
		return domain.AuthSession{}, err
	}
	return domain.AuthSession{ID: m.ID, UserID: m.UserID, TokenHash: m.TokenHash, ExpiresAt: m.ExpiresAt, CreatedAt: m.CreatedAt}, nil
}

func (r *GraphRepository) GetSessionByTokenHash(ctx context.Context, tokenHash string) (domain.AuthSession, error) {
	var m SessionModel
	if err := r.db.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&m).Error; err != nil {
		return domain.AuthSession{}, err
	}
	return domain.AuthSession{ID: m.ID, UserID: m.UserID, TokenHash: m.TokenHash, ExpiresAt: m.ExpiresAt, CreatedAt: m.CreatedAt}, nil
}

func (r *GraphRepository) DeleteSessionByTokenHash(ctx context.Context, tokenHash string) error {
	return r.db.WithContext(ctx).Where("token_hash = ?", tokenHash).Delete(&SessionModel{}).Error
}

func (r *GraphRepository) CreateAPIToken(ctx context.Context, value domain.APIToken) (domain.APIToken, error) {
	m := APITokenModel{UserID: value.UserID, Name: value.Name, TokenHash: value.TokenHash, ExpiresAt: value.ExpiresAt}
	if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
		return domain.APIToken{}, err
	}
	return domain.APIToken{ID: m.ID, UserID: m.UserID, Name: m.Name, TokenHash: m.TokenHash, ExpiresAt: m.ExpiresAt, CreatedAt: m.CreatedAt}, nil
}

func (r *GraphRepository) GetAPITokenByTokenHash(ctx context.Context, tokenHash string) (domain.APIToken, error) {
	var m APITokenModel
	if err := r.db.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&m).Error; err != nil {
		return domain.APIToken{}, err
	}
	return domain.APIToken{ID: m.ID, UserID: m.UserID, Name: m.Name, TokenHash: m.TokenHash, ExpiresAt: m.ExpiresAt, CreatedAt: m.CreatedAt}, nil
}

func (r *GraphRepository) CreateRoleIfMissing(ctx context.Context, key, name string) (uint, error) {
	m := RoleModel{Key: key, Name: name}
	err := r.db.WithContext(ctx).Where("key = ?", key).FirstOrCreate(&m).Error
	if err != nil {
		return 0, err
	}
	return m.ID, nil
}

func (r *GraphRepository) ListRoles(ctx context.Context) ([]domain.Role, error) {
	rows := make([]RoleModel, 0)
	if err := r.db.WithContext(ctx).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	result := make([]domain.Role, 0, len(rows))
	for _, m := range rows {
		result = append(result, domain.Role{ID: m.ID, Key: m.Key, Name: m.Name, CreatedAt: m.CreatedAt})
	}
	return result, nil
}

func (r *GraphRepository) CreatePermissionIfMissing(ctx context.Context, key string) (uint, error) {
	m := PermissionModel{Key: key}
	err := r.db.WithContext(ctx).Where("key = ?", key).FirstOrCreate(&m).Error
	if err != nil {
		return 0, err
	}
	return m.ID, nil
}

func (r *GraphRepository) GrantPermissionToRole(ctx context.Context, roleID, permissionID uint) error {
	m := RolePermissionModel{RoleID: roleID, PermissionID: permissionID}
	return r.db.WithContext(ctx).Where("role_id = ? AND permission_id = ?", roleID, permissionID).FirstOrCreate(&m).Error
}

func (r *GraphRepository) AssignRoleToUser(ctx context.Context, userID, roleID uint) error {
	m := UserRoleModel{UserID: userID, RoleID: roleID}
	return r.db.WithContext(ctx).Where("user_id = ? AND role_id = ?", userID, roleID).FirstOrCreate(&m).Error
}

func (r *GraphRepository) ListUsers(ctx context.Context, query string, limit int) ([]domain.User, error) {
	q := r.db.WithContext(ctx).Model(&UserModel{})
	if strings.TrimSpace(query) != "" {
		like := "%" + strings.TrimSpace(query) + "%"
		q = q.Where("email LIKE ?", like)
	}
	rows := make([]UserModel, 0)
	if err := q.Order("id DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	result := make([]domain.User, 0, len(rows))
	for _, m := range rows {
		result = append(result, domain.User{ID: m.ID, Email: m.Email, PasswordHash: m.PasswordHash, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt})
	}
	return result, nil
}

func (r *GraphRepository) GetPermissionsByUserID(ctx context.Context, userID uint) ([]string, error) {
	type row struct{ Key string }
	rows := make([]row, 0)
	err := r.db.WithContext(ctx).Raw(`
SELECT p.key
FROM permissions p
JOIN role_permissions rp ON rp.permission_id = p.id
JOIN user_roles ur ON ur.role_id = rp.role_id
WHERE ur.user_id = ?
`, userID).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(rows))
	for _, r := range rows {
		result = append(result, r.Key)
	}
	return result, nil
}

func (r *GraphRepository) CreateAuditLog(ctx context.Context, value domain.AuditLog) error {
	m := AuditLogModel{ActorUserID: value.ActorUserID, Action: value.Action, TargetType: value.TargetType, TargetID: value.TargetID, Metadata: value.Metadata}
	return r.db.WithContext(ctx).Create(&m).Error
}

func (r *GraphRepository) ListAuditLogs(ctx context.Context, limit int) ([]domain.AuditRecord, error) {
	type row struct {
		ID             uint
		ActorUserID    *uint
		ActorUserEmail string
		Action         string
		TargetType     string
		TargetID       *uint
		Metadata       string
		CreatedAt      time.Time
	}
	rows := make([]row, 0)
	err := r.db.WithContext(ctx).Raw(`
SELECT a.id,
       a.actor_user_id,
       COALESCE(u.email, '') AS actor_user_email,
       a.action,
       a.target_type,
       a.target_id,
       a.metadata,
       a.created_at
FROM audit_logs a
LEFT JOIN users u ON u.id = a.actor_user_id
ORDER BY a.id DESC
LIMIT ?
`, limit).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	result := make([]domain.AuditRecord, 0, len(rows))
	for _, m := range rows {
		result = append(result, domain.AuditRecord{
			ID:             m.ID,
			ActorUserID:    m.ActorUserID,
			ActorUserEmail: m.ActorUserEmail,
			Action:         m.Action,
			TargetType:     m.TargetType,
			TargetID:       m.TargetID,
			Metadata:       m.Metadata,
			CreatedAt:      m.CreatedAt,
		})
	}
	return result, nil
}

func (r *GraphRepository) CreateTraceRun(ctx context.Context, value domain.TraceRun) (domain.TraceRun, error) {
	m := TraceRunModel{
		ActorUserID:    value.ActorUserID,
		StartEntityID:  value.StartEntityID,
		TargetEntityID: value.TargetEntityID,
		MaxDepth:       value.MaxDepth,
		RelationKeys:   value.RelationKeys,
		HopCount:       value.HopCount,
	}
	if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
		return domain.TraceRun{}, err
	}
	return domain.TraceRun{
		ID:             m.ID,
		ActorUserID:    m.ActorUserID,
		StartEntityID:  m.StartEntityID,
		TargetEntityID: m.TargetEntityID,
		MaxDepth:       m.MaxDepth,
		RelationKeys:   m.RelationKeys,
		HopCount:       m.HopCount,
		CreatedAt:      m.CreatedAt,
	}, nil
}

func (r *GraphRepository) ListTraceRuns(ctx context.Context, actorUserID *uint, limit int) ([]domain.TraceRun, error) {
	q := r.db.WithContext(ctx).Model(&TraceRunModel{})
	if actorUserID != nil {
		q = q.Where("actor_user_id = ?", *actorUserID)
	}

	rows := make([]TraceRunModel, 0)
	if err := q.Order("created_at DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	result := make([]domain.TraceRun, 0, len(rows))
	for _, m := range rows {
		result = append(result, domain.TraceRun{
			ID:             m.ID,
			ActorUserID:    m.ActorUserID,
			StartEntityID:  m.StartEntityID,
			TargetEntityID: m.TargetEntityID,
			MaxDepth:       m.MaxDepth,
			RelationKeys:   m.RelationKeys,
			HopCount:       m.HopCount,
			CreatedAt:      m.CreatedAt,
		})
	}
	return result, nil
}
