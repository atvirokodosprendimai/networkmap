package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/atvirokodosprendimai/networkmap/internal/application"
	"github.com/atvirokodosprendimai/networkmap/internal/domain"
)

func printJSON(v any) error {
	b, err := jsonMarshal(v)
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func printKV(rows [][2]string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		_, _ = fmt.Fprintf(w, "%s\t%s\n", row[0], row[1])
	}
	_ = w.Flush()
}

func printTable(headers []string, rows [][]string) {
	if len(rows) == 0 {
		fmt.Println("no results")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, strings.Join(headers, "\t"))
	for _, row := range rows {
		_, _ = fmt.Fprintln(w, strings.Join(row, "\t"))
	}
	_ = w.Flush()
}

func formatMaybeUint(v *uint) string {
	if v == nil {
		return "-"
	}
	return strconv.FormatUint(uint64(*v), 10)
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04:05")
}

func printEntities(items []domain.Entity) {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			strconv.FormatUint(uint64(item.ID), 10),
			strconv.FormatUint(uint64(item.EntityTypeID), 10),
			item.Name,
			item.Status,
			formatTime(item.UpdatedAt),
		})
	}
	printTable([]string{"ID", "TYPE_ID", "NAME", "STATUS", "UPDATED_AT"}, rows)
}

func printEdgeSummary(item domain.EdgeSummary) {
	printKV([][2]string{
		{"id", strconv.FormatUint(uint64(item.ID), 10)},
		{"from", strconv.FormatUint(uint64(item.SubjectEntityID), 10)},
		{"relation_id", strconv.FormatUint(uint64(item.RelationTypeID), 10)},
		{"relation", item.RelationKey},
		{"to", strconv.FormatUint(uint64(item.ObjectEntityID), 10)},
		{"state", item.State},
		{"directed", strconv.FormatBool(item.Directed)},
	})
}

func printTraversal(hops []domain.TraversalHop) {
	rows := make([][]string, 0, len(hops))
	for _, hop := range hops {
		rows = append(rows, []string{
			strconv.Itoa(hop.Depth),
			strconv.FormatUint(uint64(hop.FromEntityID), 10),
			hop.RelationKey,
			strconv.FormatUint(uint64(hop.ToEntityID), 10),
			hop.Path,
		})
	}
	printTable([]string{"DEPTH", "FROM", "RELATION", "TO", "PATH"}, rows)
}

func printEntityTypes(items []domain.EntityType) {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			strconv.FormatUint(uint64(item.ID), 10),
			item.Key,
			item.Name,
			item.Description,
		})
	}
	printTable([]string{"ID", "KEY", "NAME", "DESCRIPTION"}, rows)
}

func printRelationTypes(items []domain.RelationType) {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			strconv.FormatUint(uint64(item.ID), 10),
			item.Key,
			item.Name,
			strconv.FormatBool(item.Directed),
			item.Description,
		})
	}
	printTable([]string{"ID", "KEY", "NAME", "DIRECTED", "DESCRIPTION"}, rows)
}

func printAttributeDefs(items []domain.AttributeDef) {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			strconv.FormatUint(uint64(item.ID), 10),
			item.Scope,
			item.Key,
			item.ValueKind,
			item.Description,
		})
	}
	printTable([]string{"ID", "SCOPE", "KEY", "VALUE_KIND", "DESCRIPTION"}, rows)
}

func printUsers(items []domain.User) {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			strconv.FormatUint(uint64(item.ID), 10),
			item.Email,
			formatTime(item.CreatedAt),
		})
	}
	printTable([]string{"ID", "EMAIL", "CREATED_AT"}, rows)
}

func printRoles(items []domain.Role) {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			strconv.FormatUint(uint64(item.ID), 10),
			item.Key,
			item.Name,
		})
	}
	printTable([]string{"ID", "KEY", "NAME"}, rows)
}

func printAuditRecords(items []domain.AuditRecord) {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			strconv.FormatUint(uint64(item.ID), 10),
			item.Action,
			item.TargetType,
			formatMaybeUint(item.TargetID),
			item.ActorUserEmail,
			formatTime(item.CreatedAt),
		})
	}
	printTable([]string{"ID", "ACTION", "TARGET_TYPE", "TARGET_ID", "ACTOR", "AT"}, rows)
}

func printChainProvisionResult(item application.ProvisionChainResult) {
	entityIDs := make([]string, 0, len(item.EntityIDs))
	for _, id := range item.EntityIDs {
		entityIDs = append(entityIDs, strconv.FormatUint(uint64(id), 10))
	}
	edgeIDs := make([]string, 0, len(item.EdgeIDs))
	for _, id := range item.EdgeIDs {
		edgeIDs = append(edgeIDs, strconv.FormatUint(uint64(id), 10))
	}
	printKV([][2]string{
		{"entity_ids", strings.Join(entityIDs, ",")},
		{"edge_ids", strings.Join(edgeIDs, ",")},
	})
}
