package domain

import "time"

type EntityType struct {
	ID          uint
	Key         string
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type RelationType struct {
	ID          uint
	Key         string
	Name        string
	Description string
	Directed    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Entity struct {
	ID           uint
	EntityType   EntityType
	EntityTypeID uint
	Name         string
	Status       string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type EdgeTriple struct {
	ID              uint
	SubjectEntityID uint
	RelationTypeID  uint
	ObjectEntityID  uint
	Directed        bool
	State           string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type AttributeDef struct {
	ID          uint
	Scope       string
	Key         string
	ValueKind   string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type EntityAttribute struct {
	ID             uint
	EntityID       uint
	AttributeDefID uint
	Value          string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type EdgeAttribute struct {
	ID             uint
	EdgeID         uint
	AttributeDefID uint
	Value          string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type TraversalHop struct {
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

type TraceQuery struct {
	StartEntityID  uint
	TargetEntityID *uint
	MaxDepth       int
	RelationKeys   []string
}

type EdgeSummary struct {
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

type TraceRun struct {
	ID             uint
	ActorUserID    *uint
	StartEntityID  uint
	TargetEntityID *uint
	MaxDepth       int
	RelationKeys   string
	HopCount       int
	CreatedAt      time.Time
}

type User struct {
	ID           uint
	Email        string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type AuthSession struct {
	ID        uint
	UserID    uint
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type APIToken struct {
	ID        uint
	UserID    uint
	Name      string
	TokenHash string
	ExpiresAt *time.Time
	CreatedAt time.Time
}

type AuditLog struct {
	ID          uint
	ActorUserID *uint
	Action      string
	TargetType  string
	TargetID    *uint
	Metadata    string
	CreatedAt   time.Time
}

type Identity struct {
	User        User
	Permissions map[string]struct{}
}

type Role struct {
	ID        uint
	Key       string
	Name      string
	CreatedAt time.Time
}

type AuditRecord struct {
	ID             uint
	ActorUserID    *uint
	ActorUserEmail string
	Action         string
	TargetType     string
	TargetID       *uint
	Metadata       string
	CreatedAt      time.Time
}
