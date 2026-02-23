package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/atvirokodosprendimai/networkmap/internal/domain"
)

func TestTraceHonorsDepthAndAvoidsCycles(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "networkmap_test.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := RunMigrations(ctx, db); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	repo := NewGraphRepository(db)

	entityType, err := repo.CreateEntityType(ctx, domain.EntityType{Key: "device", Name: "Device"})
	if err != nil {
		t.Fatalf("create entity type: %v", err)
	}
	relationType, err := repo.CreateRelationType(ctx, domain.RelationType{Key: "connected_to", Name: "Connected To", Directed: false})
	if err != nil {
		t.Fatalf("create relation type: %v", err)
	}

	olt, _ := repo.CreateEntity(ctx, domain.Entity{EntityTypeID: entityType.ID, Name: "OLT-PON-1", Status: "active"})
	splitter, _ := repo.CreateEntity(ctx, domain.Entity{EntityTypeID: entityType.ID, Name: "SPL-1x128", Status: "active"})
	onu, _ := repo.CreateEntity(ctx, domain.Entity{EntityTypeID: entityType.ID, Name: "ONU-77", Status: "active"})
	home, _ := repo.CreateEntity(ctx, domain.Entity{EntityTypeID: entityType.ID, Name: "Home-Router", Status: "active"})

	_, _ = repo.CreateEdge(ctx, domain.EdgeTriple{SubjectEntityID: olt.ID, RelationTypeID: relationType.ID, ObjectEntityID: splitter.ID, Directed: true, State: "active"})
	_, _ = repo.CreateEdge(ctx, domain.EdgeTriple{SubjectEntityID: splitter.ID, RelationTypeID: relationType.ID, ObjectEntityID: onu.ID, Directed: true, State: "active"})
	_, _ = repo.CreateEdge(ctx, domain.EdgeTriple{SubjectEntityID: onu.ID, RelationTypeID: relationType.ID, ObjectEntityID: home.ID, Directed: true, State: "active"})
	_, _ = repo.CreateEdge(ctx, domain.EdgeTriple{SubjectEntityID: onu.ID, RelationTypeID: relationType.ID, ObjectEntityID: olt.ID, Directed: true, State: "active"})

	hopsDepth2, err := repo.Trace(ctx, domain.TraceQuery{StartEntityID: olt.ID, MaxDepth: 2})
	if err != nil {
		t.Fatalf("trace depth2: %v", err)
	}
	if len(hopsDepth2) == 0 {
		t.Fatalf("expected hops at depth2")
	}
	for _, hop := range hopsDepth2 {
		if hop.Depth > 2 {
			t.Fatalf("unexpected hop beyond depth limit: %+v", hop)
		}
		if hop.ToEntityID == home.ID && hop.Depth <= 2 {
			t.Fatalf("home should not be reached at depth 2")
		}
	}

	hopsDepth3, err := repo.Trace(ctx, domain.TraceQuery{StartEntityID: olt.ID, MaxDepth: 3})
	if err != nil {
		t.Fatalf("trace depth3: %v", err)
	}

	var reachedHome bool
	for _, hop := range hopsDepth3 {
		if hop.ToEntityID == home.ID {
			reachedHome = true
		}
		if hop.Depth > 3 {
			t.Fatalf("unexpected hop beyond depth limit: %+v", hop)
		}
	}
	if !reachedHome {
		t.Fatalf("expected to reach home at depth3")
	}

	hopsFiltered, err := repo.Trace(ctx, domain.TraceQuery{StartEntityID: olt.ID, MaxDepth: 3, RelationKeys: []string{"contains"}})
	if err != nil {
		t.Fatalf("trace filtered: %v", err)
	}
	if len(hopsFiltered) != 0 {
		t.Fatalf("expected zero hops when relation key filter does not match")
	}
}
