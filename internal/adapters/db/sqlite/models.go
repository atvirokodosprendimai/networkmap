package sqlite

import "time"

type EntityTypeModel struct {
	ID          uint   `gorm:"primaryKey"`
	Key         string `gorm:"uniqueIndex;not null"`
	Name        string `gorm:"not null"`
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (EntityTypeModel) TableName() string { return "entity_types" }

type RelationTypeModel struct {
	ID          uint   `gorm:"primaryKey"`
	Key         string `gorm:"uniqueIndex;not null"`
	Name        string `gorm:"not null"`
	Description string
	Directed    bool `gorm:"not null;default:false"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (RelationTypeModel) TableName() string { return "relation_types" }

type EntityModel struct {
	ID           uint   `gorm:"primaryKey"`
	EntityTypeID uint   `gorm:"not null;index"`
	Name         string `gorm:"not null;index"`
	Status       string `gorm:"not null;default:'active'"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (EntityModel) TableName() string { return "entities" }

type EdgeModel struct {
	ID              uint   `gorm:"primaryKey"`
	SubjectEntityID uint   `gorm:"not null;index"`
	RelationTypeID  uint   `gorm:"not null;index"`
	ObjectEntityID  uint   `gorm:"not null;index"`
	Directed        bool   `gorm:"not null;default:false"`
	State           string `gorm:"not null;default:'active'"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (EdgeModel) TableName() string { return "edges" }

type AttributeDefModel struct {
	ID          uint   `gorm:"primaryKey"`
	Scope       string `gorm:"not null;index:idx_scope_key,unique"`
	Key         string `gorm:"not null;index:idx_scope_key,unique"`
	ValueKind   string `gorm:"not null;default:'string'"`
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (AttributeDefModel) TableName() string { return "attribute_defs" }

type EntityAttributeModel struct {
	ID             uint   `gorm:"primaryKey"`
	EntityID       uint   `gorm:"not null;index:idx_entity_attr,unique"`
	AttributeDefID uint   `gorm:"not null;index:idx_entity_attr,unique"`
	Value          string `gorm:"not null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (EntityAttributeModel) TableName() string { return "entity_attrs" }

type EdgeAttributeModel struct {
	ID             uint   `gorm:"primaryKey"`
	EdgeID         uint   `gorm:"not null;index:idx_edge_attr,unique"`
	AttributeDefID uint   `gorm:"not null;index:idx_edge_attr,unique"`
	Value          string `gorm:"not null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (EdgeAttributeModel) TableName() string { return "edge_attrs" }

type UserModel struct {
	ID           uint   `gorm:"primaryKey"`
	Email        string `gorm:"not null;uniqueIndex"`
	PasswordHash string `gorm:"not null"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (UserModel) TableName() string { return "users" }

type SessionModel struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    uint   `gorm:"not null;index"`
	TokenHash string `gorm:"not null;uniqueIndex"`
	ExpiresAt time.Time
	CreatedAt time.Time
}

func (SessionModel) TableName() string { return "sessions" }

type APITokenModel struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    uint   `gorm:"not null;index"`
	Name      string `gorm:"not null"`
	TokenHash string `gorm:"not null;uniqueIndex"`
	ExpiresAt *time.Time
	CreatedAt time.Time
}

func (APITokenModel) TableName() string { return "api_tokens" }

type RoleModel struct {
	ID        uint   `gorm:"primaryKey"`
	Key       string `gorm:"not null;uniqueIndex"`
	Name      string `gorm:"not null"`
	CreatedAt time.Time
}

func (RoleModel) TableName() string { return "roles" }

type PermissionModel struct {
	ID        uint   `gorm:"primaryKey"`
	Key       string `gorm:"not null;uniqueIndex"`
	CreatedAt time.Time
}

func (PermissionModel) TableName() string { return "permissions" }

type UserRoleModel struct {
	ID        uint `gorm:"primaryKey"`
	UserID    uint `gorm:"not null;index:idx_user_role,unique"`
	RoleID    uint `gorm:"not null;index:idx_user_role,unique"`
	CreatedAt time.Time
}

func (UserRoleModel) TableName() string { return "user_roles" }

type RolePermissionModel struct {
	ID           uint `gorm:"primaryKey"`
	RoleID       uint `gorm:"not null;index:idx_role_perm,unique"`
	PermissionID uint `gorm:"not null;index:idx_role_perm,unique"`
	CreatedAt    time.Time
}

func (RolePermissionModel) TableName() string { return "role_permissions" }

type AuditLogModel struct {
	ID          uint `gorm:"primaryKey"`
	ActorUserID *uint
	Action      string `gorm:"not null;index"`
	TargetType  string `gorm:"not null;index"`
	TargetID    *uint
	Metadata    string
	CreatedAt   time.Time
}

func (AuditLogModel) TableName() string { return "audit_logs" }

type TraceRunModel struct {
	ID             uint `gorm:"primaryKey"`
	ActorUserID    *uint
	StartEntityID  uint `gorm:"not null;index"`
	TargetEntityID *uint
	MaxDepth       int    `gorm:"not null"`
	RelationKeys   string `gorm:"not null;default:''"`
	HopCount       int    `gorm:"not null;default:0"`
	CreatedAt      time.Time
}

func (TraceRunModel) TableName() string { return "trace_runs" }
