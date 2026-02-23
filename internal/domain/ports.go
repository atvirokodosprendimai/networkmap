package domain

import "context"

type GraphRepository interface {
	CreateEntityType(ctx context.Context, value EntityType) (EntityType, error)
	ListEntityTypes(ctx context.Context, query string, limit int) ([]EntityType, error)
	CreateRelationType(ctx context.Context, value RelationType) (RelationType, error)
	ListRelationTypes(ctx context.Context, query string, limit int) ([]RelationType, error)
	CreateEntity(ctx context.Context, value Entity) (Entity, error)
	ListEntities(ctx context.Context, entityTypeID *uint, query string, limit int) ([]Entity, error)
	ListEdges(ctx context.Context, limit int) ([]EdgeSummary, error)
	CreateEdge(ctx context.Context, value EdgeTriple) (EdgeTriple, error)
	GetEdgeByID(ctx context.Context, edgeID uint) (EdgeSummary, error)
	UpdateEdgeState(ctx context.Context, edgeID uint, state string) (EdgeTriple, error)
	UpsertAttributeDef(ctx context.Context, value AttributeDef) (AttributeDef, error)
	ListAttributeDefs(ctx context.Context, scope, query string, limit int) ([]AttributeDef, error)
	UpsertEntityAttribute(ctx context.Context, value EntityAttribute) (EntityAttribute, error)
	UpsertEdgeAttribute(ctx context.Context, value EdgeAttribute) (EdgeAttribute, error)
	Trace(ctx context.Context, query TraceQuery) ([]TraversalHop, error)

	CreateUser(ctx context.Context, value User) (User, error)
	CountUsers(ctx context.Context) (int64, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
	GetUserByID(ctx context.Context, id uint) (User, error)
	CreateSession(ctx context.Context, value AuthSession) (AuthSession, error)
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (AuthSession, error)
	DeleteSessionByTokenHash(ctx context.Context, tokenHash string) error
	CreateAPIToken(ctx context.Context, value APIToken) (APIToken, error)
	GetAPITokenByTokenHash(ctx context.Context, tokenHash string) (APIToken, error)
	CreateRoleIfMissing(ctx context.Context, key, name string) (uint, error)
	ListRoles(ctx context.Context) ([]Role, error)
	CreatePermissionIfMissing(ctx context.Context, key string) (uint, error)
	GrantPermissionToRole(ctx context.Context, roleID, permissionID uint) error
	AssignRoleToUser(ctx context.Context, userID, roleID uint) error
	ListUsers(ctx context.Context, query string, limit int) ([]User, error)
	GetPermissionsByUserID(ctx context.Context, userID uint) ([]string, error)
	CreateAuditLog(ctx context.Context, value AuditLog) error
	ListAuditLogs(ctx context.Context, limit int) ([]AuditRecord, error)
	CreateTraceRun(ctx context.Context, value TraceRun) (TraceRun, error)
	ListTraceRuns(ctx context.Context, actorUserID *uint, limit int) ([]TraceRun, error)
}
