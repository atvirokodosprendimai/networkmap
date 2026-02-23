package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/atvirokodosprendimai/networkmap/internal/application"
	"github.com/atvirokodosprendimai/networkmap/internal/domain"
	"github.com/atvirokodosprendimai/networkmap/internal/ui"
	"github.com/go-chi/chi/v5"
	"github.com/starfederation/datastar-go/datastar"
)

const sessionCookieName = "nm_session"

type contextKey string

const identityKey contextKey = "identity"

type Handler struct {
	service *application.GraphService
}

func NewRouter(service *application.GraphService) http.Handler {
	h := &Handler{service: service}
	r := chi.NewRouter()

	r.Get("/login", h.handleLoginPage)
	r.Post("/login", h.handleLogin)
	r.Post("/logout", h.handleLogout)

	r.Route("/api", func(api chi.Router) {
		api.Post("/auth/login", h.handleAPILogin)
		api.With(h.requireAuthAPI("graph.read")).Get("/auth/whoami", h.handleAPIWhoAmI)
		api.With(h.requireAuthAPI("graph.read")).Post("/auth/logout", h.handleAPILogout)
		api.With(h.requireAuthAPI("graph.read")).Get("/catalog/entity-types", h.handleAPIListEntityTypes)
		api.With(h.requireAuthAPI("graph.write")).Post("/catalog/entity-types", h.handleAPICreateEntityType)
		api.With(h.requireAuthAPI("graph.read")).Get("/catalog/relation-types", h.handleAPIListRelationTypes)
		api.With(h.requireAuthAPI("graph.write")).Post("/catalog/relation-types", h.handleAPICreateRelationType)
		api.With(h.requireAuthAPI("graph.read")).Get("/catalog/attribute-defs", h.handleAPIListAttributeDefs)
		api.With(h.requireAuthAPI("graph.write")).Post("/catalog/attribute-defs", h.handleAPIUpsertAttributeDef)
		api.With(h.requireAuthAPI("graph.read")).Get("/access/users", h.handleAPIListUsers)
		api.With(h.requireAuthAPI("graph.write")).Post("/access/users", h.handleAPICreateUser)
		api.With(h.requireAuthAPI("graph.read")).Get("/access/roles", h.handleAPIListRoles)
		api.With(h.requireAuthAPI("graph.write")).Post("/access/assign-role", h.handleAPIAssignRole)
		api.With(h.requireAuthAPI("graph.read")).Get("/audit/logs", h.handleAPIListAuditLogs)

		api.With(h.requireAuthAPI("graph.read")).Get("/entities", h.handleAPIListEntities)
		api.With(h.requireAuthAPI("graph.write")).Post("/entities", h.handleAPICreateEntity)
		api.With(h.requireAuthAPI("graph.write")).Post("/edges/connect", h.handleAPICreateEdge)
		api.With(h.requireAuthAPI("graph.write")).Post("/edges/cut", h.handleAPICutEdge)
		api.With(h.requireAuthAPI("graph.write")).Post("/workflows/provision-chain", h.handleAPIProvisionChain)
		api.With(h.requireAuthAPI("graph.read")).Post("/trace", h.handleAPITrace)
	})

	r.With(h.requireAuthGUI("graph.read")).Get("/", h.handleHomeRedirect)
	r.With(h.requireAuthGUI("graph.read")).Get("/wizard", h.handleWizard)
	r.With(h.requireAuthGUI("graph.read")).Get("/dashboard", h.handleDashboard)
	r.With(h.requireAuthGUI("graph.read")).Get("/map", h.handleMap)
	r.With(h.requireAuthGUI("graph.read")).Get("/workflows", h.handleWorkflows)
	r.With(h.requireAuthGUI("graph.read")).Get("/inventory", h.handleInventory)
	r.With(h.requireAuthGUI("graph.read")).Get("/admin/catalog", h.handleAdminCatalog)
	r.With(h.requireAuthGUI("graph.read")).Get("/admin/access", h.handleAdminAccess)
	r.With(h.requireAuthGUI("graph.read")).Get("/admin/audit", h.handleAdminAudit)
	r.With(h.requireAuthGUI("graph.read")).Post("/inventory/search", h.handleInventorySearch)
	r.With(h.requireAuthGUI("graph.read")).Post("/pickers/entities", h.handlePickerEntities)
	r.With(h.requireAuthGUI("graph.read")).Post("/pickers/relations", h.handlePickerRelations)

	r.With(h.requireAuthGUI("graph.write")).Post("/workflows/connect", h.handleWorkflowConnect)
	r.With(h.requireAuthGUI("graph.read")).Post("/workflows/connect/targets", h.handleWorkflowConnectTargets)
	r.With(h.requireAuthGUI("graph.write")).Post("/workflows/cut", h.handleWorkflowCut)
	r.With(h.requireAuthGUI("graph.write")).Post("/workflows/splice", h.handleWorkflowSplice)
	r.With(h.requireAuthGUI("graph.write")).Post("/workflows/provision/chain", h.handleWorkflowProvisionChain)
	r.With(h.requireAuthGUI("graph.read")).Post("/workflows/cut/preview", h.handleWorkflowCutPreview)
	r.With(h.requireAuthGUI("graph.read")).Post("/workflows/splice/preview", h.handleWorkflowSplicePreview)

	r.With(h.requireAuthGUI("graph.write")).Post("/commands/entity-types", h.handleCreateEntityType)
	r.With(h.requireAuthGUI("graph.write")).Post("/commands/relation-types", h.handleCreateRelationType)
	r.With(h.requireAuthGUI("graph.write")).Post("/commands/entities", h.handleCreateEntity)
	r.With(h.requireAuthGUI("graph.write")).Post("/commands/edges", h.handleCreateEdge)
	r.With(h.requireAuthGUI("graph.write")).Post("/commands/attribute-defs", h.handleUpsertAttributeDef)
	r.With(h.requireAuthGUI("graph.write")).Post("/commands/entity-attrs", h.handleSetEntityAttr)
	r.With(h.requireAuthGUI("graph.write")).Post("/commands/edge-attrs", h.handleSetEdgeAttr)
	r.With(h.requireAuthGUI("graph.read")).Post("/queries/trace", h.handleTrace)
	r.With(h.requireAuthGUI("graph.write")).Post("/admin/catalog/entity-types/create", h.handleCreateEntityType)
	r.With(h.requireAuthGUI("graph.write")).Post("/admin/catalog/relation-types/create", h.handleCreateRelationType)
	r.With(h.requireAuthGUI("graph.write")).Post("/admin/catalog/attribute-defs/upsert", h.handleUpsertAttributeDef)
	r.With(h.requireAuthGUI("graph.write")).Post("/admin/access/users/create", h.handleAdminCreateUser)
	r.With(h.requireAuthGUI("graph.write")).Post("/admin/access/roles/assign", h.handleAdminAssignRole)

	return r
}

func (h *Handler) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if err := ui.LoginPage("").Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.Form.Get("email"))
	password := r.Form.Get("password")

	_, token, err := h.service.LoginWithSession(r.Context(), email, password, 12*time.Hour)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = ui.LoginPage("invalid credentials").Render(r.Context(), w)
		return
	}

	h.setSessionCookie(w, token)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookieName)
	if err == nil && c.Value != "" {
		_ = h.service.LogoutSession(r.Context(), c.Value)
	}
	h.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) handleHomeRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if err := ui.DashboardPage(currentUserEmail(r.Context())).Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) handleWizard(w http.ResponseWriter, r *http.Request) {
	entityTypes, _ := h.service.ListEntityTypes(r.Context(), "", 300)
	relationTypes, _ := h.service.ListRelationTypes(r.Context(), "", 300)
	entities, _ := h.service.ListEntities(r.Context(), nil, "", 300)
	if err := ui.WizardPage(entityTypes, relationTypes, entities, currentUserEmail(r.Context())).Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) handleMap(w http.ResponseWriter, r *http.Request) {
	var actorUserID *uint
	if identity, ok := identityFromContext(r.Context()); ok {
		actorUserID = &identity.User.ID
	}
	runs, _ := h.service.ListTraceRuns(r.Context(), actorUserID, 30)
	entities, _ := h.service.ListEntities(r.Context(), nil, "", 300)
	if err := ui.MapPage(runs, entities, currentUserEmail(r.Context())).Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) handleWorkflows(w http.ResponseWriter, r *http.Request) {
	entities, _ := h.service.ListEntities(r.Context(), nil, "", 300)
	relations, _ := h.service.ListRelationTypes(r.Context(), "", 200)
	edges, _ := h.service.ListEdges(r.Context(), 300)
	if err := ui.WorkflowsPage(entities, relations, edges, currentUserEmail(r.Context())).Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) handleInventory(w http.ResponseWriter, r *http.Request) {
	entities, err := h.service.ListEntities(r.Context(), nil, "", 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	entityTypes, err := h.service.ListEntityTypes(r.Context(), "", 300)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := ui.InventoryPage(entities, entityTypes, currentUserEmail(r.Context())).Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) handleAdminCatalog(w http.ResponseWriter, r *http.Request) {
	entityTypes, _ := h.service.ListEntityTypes(r.Context(), "", 300)
	relationTypes, _ := h.service.ListRelationTypes(r.Context(), "", 300)
	attrDefs, _ := h.service.ListAttributeDefs(r.Context(), "", "", 300)
	if err := ui.AdminCatalogPage(entityTypes, relationTypes, attrDefs, currentUserEmail(r.Context())).Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) handleAdminAccess(w http.ResponseWriter, r *http.Request) {
	users, _ := h.service.ListUsers(r.Context(), "", 300)
	roles, _ := h.service.ListRoles(r.Context())
	if err := ui.AdminAccessPage(users, roles, currentUserEmail(r.Context())).Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	logs, _ := h.service.ListAuditLogs(r.Context(), 300)
	if err := ui.AdminAuditPage(logs, currentUserEmail(r.Context())).Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type inventorySignals struct {
	InventoryQuery  string `json:"inventoryQuery"`
	InventoryTypeID string `json:"inventoryTypeId"`
}

func (h *Handler) handleInventorySearch(w http.ResponseWriter, r *http.Request) {
	var sig inventorySignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, "invalid inventory query")
		return
	}

	var typeID *uint
	if strings.TrimSpace(sig.InventoryTypeID) != "" {
		parsed, err := strconv.ParseUint(strings.TrimSpace(sig.InventoryTypeID), 10, 64)
		if err != nil {
			h.renderFlash(r.Context(), w, http.StatusBadRequest, "Type ID must be a number")
			return
		}
		v := uint(parsed)
		typeID = &v
	}

	entities, err := h.service.ListEntities(r.Context(), typeID, sig.InventoryQuery, 200)
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := ui.InventoryResults(entities).Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type pickerSignals struct {
	EntityPickerQ   string `json:"entityPickerQ"`
	RelationPickerQ string `json:"relationPickerQ"`
}

func (h *Handler) handlePickerEntities(w http.ResponseWriter, r *http.Request) {
	var sig pickerSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		http.Error(w, "invalid picker query", http.StatusBadRequest)
		return
	}
	entities, err := h.service.ListEntities(r.Context(), nil, sig.EntityPickerQ, 10)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := ui.PickerEntities(entities).Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) handlePickerRelations(w http.ResponseWriter, r *http.Request) {
	var sig pickerSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		http.Error(w, "invalid picker query", http.StatusBadRequest)
		return
	}
	relations, err := h.service.ListRelationTypes(r.Context(), sig.RelationPickerQ, 10)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := ui.PickerRelations(relations).Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) requireAuthGUI(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := h.authenticateRequest(r)
			if !ok {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			if !h.service.Can(identity, permission) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey, identity)))
		})
	}
}

func (h *Handler) requireAuthAPI(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := h.authenticateRequest(r)
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
				return
			}
			if !h.service.Can(identity, permission) {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey, identity)))
		})
	}
}

func (h *Handler) authenticateRequest(r *http.Request) (domain.Identity, bool) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		token := strings.TrimSpace(authHeader[7:])
		identity, err := h.service.AuthenticateBearerToken(r.Context(), token)
		if err == nil {
			return identity, true
		}
	}

	c, err := r.Cookie(sessionCookieName)
	if err == nil && strings.TrimSpace(c.Value) != "" {
		identity, authErr := h.service.AuthenticateSession(r.Context(), c.Value)
		if authErr == nil {
			return identity, true
		}
	}

	return domain.Identity{}, false
}

func identityFromContext(ctx context.Context) (domain.Identity, bool) {
	value := ctx.Value(identityKey)
	if value == nil {
		return domain.Identity{}, false
	}
	identity, ok := value.(domain.Identity)
	return identity, ok
}

func currentUserEmail(ctx context.Context) string {
	identity, ok := identityFromContext(ctx)
	if !ok {
		return ""
	}
	return identity.User.Email
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
	})
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

type createEntityTypeSignals struct {
	EntityTypeKey         string `json:"entityTypeKey"`
	EntityTypeName        string `json:"entityTypeName"`
	EntityTypeDescription string `json:"entityTypeDescription"`
}

func (h *Handler) handleCreateEntityType(w http.ResponseWriter, r *http.Request) {
	var sig createEntityTypeSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, "invalid signals")
		return
	}
	v, err := h.service.CreateEntityType(r.Context(), sig.EntityTypeKey, sig.EntityTypeName, sig.EntityTypeDescription)
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeAudit(r.Context(), "graph.entity_type.create", "entity_type", &v.ID)
	message := fmt.Sprintf("Created entity type #%d (%s)", v.ID, v.Key)
	pagePath := pagePathFromReferer(r)

	if pagePath == "/wizard" {
		entityTypes, _ := h.service.ListEntityTypes(r.Context(), "", 300)
		relationTypes, _ := h.service.ListRelationTypes(r.Context(), "", 300)
		entities, _ := h.service.ListEntities(r.Context(), nil, "", 300)
		renderHTMLFragments(r.Context(), w, http.StatusOK,
			ui.Flash(message, "info"),
			ui.WizardStatusBar(len(entityTypes), len(relationTypes), len(entities)),
			ui.WizardEntityTypeSelect(entityTypes),
			ui.WizardStep2Lock(len(entityTypes) > 0),
			ui.WizardStep3Lock(len(entityTypes) > 0),
		)
		return
	}

	if pagePath == "/admin/catalog" {
		entityTypes, _ := h.service.ListEntityTypes(r.Context(), "", 300)
		renderHTMLFragments(r.Context(), w, http.StatusOK,
			ui.Flash(message, "info"),
			ui.EntityTypesTable(entityTypes),
		)
		return
	}

	h.renderFlash(r.Context(), w, http.StatusOK, message)
}

type createRelationTypeSignals struct {
	RelationTypeKey         string `json:"relationTypeKey"`
	RelationTypeName        string `json:"relationTypeName"`
	RelationTypeDescription string `json:"relationTypeDescription"`
	RelationDirected        bool   `json:"relationDirected"`
}

func (h *Handler) handleCreateRelationType(w http.ResponseWriter, r *http.Request) {
	var sig createRelationTypeSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, "invalid signals")
		return
	}
	v, err := h.service.CreateRelationType(r.Context(), sig.RelationTypeKey, sig.RelationTypeName, sig.RelationTypeDescription, sig.RelationDirected)
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeAudit(r.Context(), "graph.relation_type.create", "relation_type", &v.ID)
	message := fmt.Sprintf("Created relation type #%d (%s)", v.ID, v.Key)
	pagePath := pagePathFromReferer(r)

	if pagePath == "/wizard" {
		entityTypes, _ := h.service.ListEntityTypes(r.Context(), "", 300)
		relationTypes, _ := h.service.ListRelationTypes(r.Context(), "", 300)
		entities, _ := h.service.ListEntities(r.Context(), nil, "", 300)
		renderHTMLFragments(r.Context(), w, http.StatusOK,
			ui.Flash(message, "info"),
			ui.WizardStatusBar(len(entityTypes), len(relationTypes), len(entities)),
			ui.WizardRelationTypeSelect(relationTypes),
			ui.WizardStep4Lock(len(relationTypes) > 0, len(entities)),
		)
		return
	}

	if pagePath == "/admin/catalog" {
		relationTypes, _ := h.service.ListRelationTypes(r.Context(), "", 300)
		renderHTMLFragments(r.Context(), w, http.StatusOK,
			ui.Flash(message, "info"),
			ui.RelationTypesTable(relationTypes),
		)
		return
	}

	h.renderFlash(r.Context(), w, http.StatusOK, message)
}

type createEntitySignals struct {
	EntityTypeID string `json:"entityTypeId"`
	EntityName   string `json:"entityName"`
	EntityStatus string `json:"entityStatus"`
}

func (h *Handler) handleCreateEntity(w http.ResponseWriter, r *http.Request) {
	var sig createEntitySignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, "invalid signals")
		return
	}
	entityTypeID, err := parseRequiredUintSignal(sig.EntityTypeID, "entityTypeId")
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	v, err := h.service.CreateEntity(r.Context(), entityTypeID, sig.EntityName, sig.EntityStatus)
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeAudit(r.Context(), "graph.entity.create", "entity", &v.ID)
	message := fmt.Sprintf("Created entity #%d (%s)", v.ID, v.Name)
	pagePath := pagePathFromReferer(r)

	if pagePath == "/wizard" {
		entityTypes, _ := h.service.ListEntityTypes(r.Context(), "", 300)
		relationTypes, _ := h.service.ListRelationTypes(r.Context(), "", 300)
		entities, _ := h.service.ListEntities(r.Context(), nil, "", 300)
		renderHTMLFragments(r.Context(), w, http.StatusOK,
			ui.Flash(message, "info"),
			ui.WizardStatusBar(len(entityTypes), len(relationTypes), len(entities)),
			ui.WizardEntitySelectA(entities),
			ui.WizardEntitySelectB(entities),
			ui.WizardStep4Lock(len(relationTypes) > 0, len(entities)),
		)
		return
	}

	if pagePath == "/inventory" {
		entities, _ := h.service.ListEntities(r.Context(), nil, "", 200)
		renderHTMLFragments(r.Context(), w, http.StatusOK,
			ui.Flash(message, "info"),
			ui.InventoryResults(entities),
		)
		return
	}

	h.renderFlash(r.Context(), w, http.StatusOK, message)
}

type createEdgeSignals struct {
	EdgeSubjectID      string `json:"edgeSubjectId"`
	EdgeRelationTypeID string `json:"edgeRelationTypeId"`
	EdgeObjectID       string `json:"edgeObjectId"`
	EdgeDirected       bool   `json:"edgeDirected"`
	EdgeState          string `json:"edgeState"`
}

func (h *Handler) handleCreateEdge(w http.ResponseWriter, r *http.Request) {
	var sig createEdgeSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, "invalid signals")
		return
	}
	subjectID, err := parseRequiredUintSignal(sig.EdgeSubjectID, "edgeSubjectId")
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	relationTypeID, err := parseRequiredUintSignal(sig.EdgeRelationTypeID, "edgeRelationTypeId")
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	objectID, err := parseRequiredUintSignal(sig.EdgeObjectID, "edgeObjectId")
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	v, err := h.service.Connect(r.Context(), subjectID, relationTypeID, objectID, sig.EdgeDirected, sig.EdgeState)
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeAudit(r.Context(), "graph.edge.create", "edge", &v.ID)
	message := fmt.Sprintf("Created edge #%d (%d -> %d)", v.ID, v.SubjectEntityID, v.ObjectEntityID)
	pagePath := pagePathFromReferer(r)
	if pagePath == "/workflows" {
		edges, _ := h.service.ListEdges(r.Context(), 300)
		renderHTMLFragments(r.Context(), w, http.StatusOK,
			ui.Flash(message, "info"),
			ui.CutEdgeSelect(edges),
			ui.CutEdgeQuickFill(edges),
		)
		return
	}
	h.renderFlash(r.Context(), w, http.StatusOK, message)
}

func (h *Handler) handleWorkflowConnect(w http.ResponseWriter, r *http.Request) {
	h.handleCreateEdge(w, r)
}

type connectTargetSignals struct {
	EdgeSubjectID   string `json:"edgeSubjectId"`
	EdgeObjectQuery string `json:"edgeObjectQuery"`
}

func (h *Handler) handleWorkflowConnectTargets(w http.ResponseWriter, r *http.Request) {
	var sig connectTargetSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		http.Error(w, "invalid target query", http.StatusBadRequest)
		return
	}
	entities, err := h.service.ListEntities(r.Context(), nil, sig.EdgeObjectQuery, 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var subjectID uint
	if parsed, err := parseOptionalUintSignal(sig.EdgeSubjectID, "edgeSubjectId"); err == nil && parsed != nil {
		subjectID = *parsed
	}
	filtered := make([]domain.Entity, 0, len(entities))
	for _, e := range entities {
		if subjectID != 0 && e.ID == subjectID {
			continue
		}
		filtered = append(filtered, e)
	}
	if err := ui.ConnectTargetSelect(filtered).Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type cutSignals struct {
	CutEdgeID string `json:"cutEdgeId"`
}

func (h *Handler) handleWorkflowCut(w http.ResponseWriter, r *http.Request) {
	var sig cutSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, "invalid cut payload")
		return
	}
	edgeID, err := parseRequiredUintSignal(sig.CutEdgeID, "cutEdgeId")
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	v, err := h.service.CutEdge(r.Context(), edgeID)
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeAudit(r.Context(), "graph.edge.cut", "edge", &v.ID)
	message := fmt.Sprintf("Edge #%d marked as cut", v.ID)
	pagePath := pagePathFromReferer(r)
	if pagePath == "/workflows" {
		edges, _ := h.service.ListEdges(r.Context(), 300)
		renderHTMLFragments(r.Context(), w, http.StatusOK,
			ui.Flash(message, "info"),
			ui.CutEdgeSelect(edges),
			ui.CutEdgeQuickFill(edges),
		)
		return
	}
	h.renderFlash(r.Context(), w, http.StatusOK, message)
}

func (h *Handler) handleWorkflowCutPreview(w http.ResponseWriter, r *http.Request) {
	var sig cutSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		http.Error(w, "invalid preview payload", http.StatusBadRequest)
		return
	}
	edgeID, err := parseRequiredUintSignal(sig.CutEdgeID, "cutEdgeId")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	edge, err := h.service.GetEdgeByID(r.Context(), edgeID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hops, _ := h.service.Trace(r.Context(), domain.TraceQuery{StartEntityID: edge.SubjectEntityID, MaxDepth: 3})
	if err := ui.CutPreview(edge, len(hops)).Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type spliceSignals struct {
	SpliceFiberA         string `json:"spliceFiberA"`
	SpliceRelationTypeID string `json:"spliceRelationTypeId"`
	SpliceFiberB         string `json:"spliceFiberB"`
}

type provisionChainSignals struct {
	ChainNodes     string `json:"chainNodes"`
	ChainRelations string `json:"chainRelations"`
	ChainAttrs     string `json:"chainAttrs"`
	ChainState     string `json:"chainState"`
}

func (h *Handler) handleWorkflowSplice(w http.ResponseWriter, r *http.Request) {
	var sig spliceSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, "invalid splice payload")
		return
	}
	fiberA, err := parseRequiredUintSignal(sig.SpliceFiberA, "spliceFiberA")
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	relationTypeID, err := parseRequiredUintSignal(sig.SpliceRelationTypeID, "spliceRelationTypeId")
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	fiberB, err := parseRequiredUintSignal(sig.SpliceFiberB, "spliceFiberB")
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	v, err := h.service.Connect(r.Context(), fiberA, relationTypeID, fiberB, false, "active")
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeAudit(r.Context(), "graph.splice.create", "edge", &v.ID)
	message := fmt.Sprintf("Splice edge #%d created", v.ID)
	pagePath := pagePathFromReferer(r)
	if pagePath == "/workflows" {
		edges, _ := h.service.ListEdges(r.Context(), 300)
		renderHTMLFragments(r.Context(), w, http.StatusOK,
			ui.Flash(message, "info"),
			ui.CutEdgeSelect(edges),
			ui.CutEdgeQuickFill(edges),
		)
		return
	}
	h.renderFlash(r.Context(), w, http.StatusOK, message)
}

func (h *Handler) handleWorkflowProvisionChain(w http.ResponseWriter, r *http.Request) {
	var sig provisionChainSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, "invalid chain payload")
		return
	}
	nodes, err := parseChainNodes(sig.ChainNodes)
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	rels, err := parseChainRelations(sig.ChainRelations)
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.service.ProvisionChain(r.Context(), application.ProvisionChainInput{
		Nodes:      nodes,
		Edges:      rels,
		Attributes: parseEntityAttrs(sig.ChainAttrs),
		State:      sig.ChainState,
	})
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	var targetID *uint
	if len(out.EntityIDs) > 0 {
		targetID = &out.EntityIDs[0]
	}
	h.writeAudit(r.Context(), "workflow.provision.chain", "entity", targetID)
	edges, _ := h.service.ListEdges(r.Context(), 300)
	entities, _ := h.service.ListEntities(r.Context(), nil, "", 200)
	renderHTMLFragments(r.Context(), w, http.StatusOK,
		ui.Flash("Provisioned chain successfully", "info"),
		ui.CutEdgeSelect(edges),
		ui.CutEdgeQuickFill(edges),
		ui.InventoryResults(entities),
	)
}

func (h *Handler) handleWorkflowSplicePreview(w http.ResponseWriter, r *http.Request) {
	var sig spliceSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		http.Error(w, "invalid preview payload", http.StatusBadRequest)
		return
	}
	fiberA, err := parseRequiredUintSignal(sig.SpliceFiberA, "spliceFiberA")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fiberB, err := parseRequiredUintSignal(sig.SpliceFiberB, "spliceFiberB")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hops, _ := h.service.Trace(r.Context(), domain.TraceQuery{StartEntityID: fiberA, TargetEntityID: &fiberB, MaxDepth: 8})
	if err := ui.SplicePreview(len(hops)).Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type upsertAttrDefSignals struct {
	AttrDefScope       string `json:"attrDefScope"`
	AttrDefKey         string `json:"attrDefKey"`
	AttrDefValueKind   string `json:"attrDefValueKind"`
	AttrDefDescription string `json:"attrDefDescription"`
}

func (h *Handler) handleUpsertAttributeDef(w http.ResponseWriter, r *http.Request) {
	var sig upsertAttrDefSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, "invalid signals")
		return
	}
	v, err := h.service.UpsertAttributeDef(r.Context(), sig.AttrDefScope, sig.AttrDefKey, sig.AttrDefValueKind, sig.AttrDefDescription)
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeAudit(r.Context(), "graph.attribute_def.upsert", "attribute_def", &v.ID)
	message := fmt.Sprintf("Upserted attribute def #%d (%s:%s)", v.ID, v.Scope, v.Key)
	pagePath := pagePathFromReferer(r)
	if pagePath == "/admin/catalog" {
		attrDefs, _ := h.service.ListAttributeDefs(r.Context(), "", "", 300)
		renderHTMLFragments(r.Context(), w, http.StatusOK,
			ui.Flash(message, "info"),
			ui.AttributeDefsTable(attrDefs),
		)
		return
	}
	h.renderFlash(r.Context(), w, http.StatusOK, message)
}

type setEntityAttrSignals struct {
	EntityAttrEntityID uint   `json:"entityAttrEntityId"`
	EntityAttrDefID    uint   `json:"entityAttrDefId"`
	EntityAttrValue    string `json:"entityAttrValue"`
}

func (h *Handler) handleSetEntityAttr(w http.ResponseWriter, r *http.Request) {
	var sig setEntityAttrSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, "invalid signals")
		return
	}
	v, err := h.service.SetEntityAttribute(r.Context(), sig.EntityAttrEntityID, sig.EntityAttrDefID, sig.EntityAttrValue)
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeAudit(r.Context(), "graph.entity_attribute.upsert", "entity_attribute", &v.ID)
	h.renderFlash(r.Context(), w, http.StatusOK, fmt.Sprintf("Set entity attribute #%d", v.ID))
}

type setEdgeAttrSignals struct {
	EdgeAttrEdgeID uint   `json:"edgeAttrEdgeId"`
	EdgeAttrDefID  uint   `json:"edgeAttrDefId"`
	EdgeAttrValue  string `json:"edgeAttrValue"`
}

type adminCreateUserSignals struct {
	NewUserEmail    string `json:"newUserEmail"`
	NewUserPassword string `json:"newUserPassword"`
	NewUserRoleID   string `json:"newUserRoleId"`
}

func (h *Handler) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var sig adminCreateUserSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, "invalid user payload")
		return
	}
	roleID := uint(0)
	if parsed, err := parseOptionalUintSignal(sig.NewUserRoleID, "newUserRoleId"); err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	} else if parsed != nil {
		roleID = *parsed
	}
	u, err := h.service.CreateUser(r.Context(), sig.NewUserEmail, sig.NewUserPassword, roleID)
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeAudit(r.Context(), "access.user.create", "user", &u.ID)
	message := fmt.Sprintf("User #%d created", u.ID)
	users, _ := h.service.ListUsers(r.Context(), "", 300)
	renderHTMLFragments(r.Context(), w, http.StatusOK,
		ui.Flash(message, "info"),
		ui.AdminUsersTable(users),
		ui.AdminAssignUserSelect(users),
	)
}

type adminAssignRoleSignals struct {
	AssignUserID string `json:"assignUserId"`
	AssignRoleID string `json:"assignRoleId"`
}

func (h *Handler) handleAdminAssignRole(w http.ResponseWriter, r *http.Request) {
	var sig adminAssignRoleSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, "invalid role assignment payload")
		return
	}
	userID, err := parseRequiredUintSignal(sig.AssignUserID, "assignUserId")
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	roleID, err := parseRequiredUintSignal(sig.AssignRoleID, "assignRoleId")
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.service.AssignRole(r.Context(), userID, roleID); err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeAudit(r.Context(), "access.role.assign", "user", &userID)
	h.renderFlash(r.Context(), w, http.StatusOK, "Role assigned")
}

func (h *Handler) handleSetEdgeAttr(w http.ResponseWriter, r *http.Request) {
	var sig setEdgeAttrSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, "invalid signals")
		return
	}
	v, err := h.service.SetEdgeAttribute(r.Context(), sig.EdgeAttrEdgeID, sig.EdgeAttrDefID, sig.EdgeAttrValue)
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeAudit(r.Context(), "graph.edge_attribute.upsert", "edge_attribute", &v.ID)
	h.renderFlash(r.Context(), w, http.StatusOK, fmt.Sprintf("Set edge attribute #%d", v.ID))
}

type traceSignals struct {
	TraceStartEntityID  string `json:"traceStartEntityId"`
	TraceTargetEntityID string `json:"traceTargetEntityId"`
	TraceMaxDepth       int    `json:"traceMaxDepth"`
	TraceRelationKeys   string `json:"traceRelationKeys"`
}

func (h *Handler) handleTrace(w http.ResponseWriter, r *http.Request) {
	q, err := readTraceSignals(r)
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	hops, err := h.service.Trace(r.Context(), q)
	if err != nil {
		h.renderFlash(r.Context(), w, http.StatusBadRequest, err.Error())
		return
	}
	if identity, ok := identityFromContext(r.Context()); ok {
		_ = h.service.SaveTraceRun(r.Context(), &identity.User.ID, q, len(hops))
	}
	if err := ui.TraceResults(hops).Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type apiLoginRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	Mode      string `json:"mode"`
	TokenName string `json:"token_name"`
}

func (h *Handler) handleAPILogin(w http.ResponseWriter, r *http.Request) {
	var req apiLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid payload"})
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "token"
	}

	if mode == "session" {
		u, token, err := h.service.LoginWithSession(r.Context(), req.Email, req.Password, 12*time.Hour)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
			return
		}
		h.setSessionCookie(w, token)
		writeJSON(w, http.StatusOK, map[string]any{"user_id": u.ID, "email": u.Email, "mode": "session"})
		return
	}

	u, token, err := h.service.LoginWithAPIToken(r.Context(), req.Email, req.Password, req.TokenName, nil)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user_id": u.ID, "email": u.Email, "token": token, "mode": "token"})
}

func (h *Handler) handleAPIWhoAmI(w http.ResponseWriter, r *http.Request) {
	identity, ok := identityFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	perms := make([]string, 0, len(identity.Permissions))
	for p := range identity.Permissions {
		perms = append(perms, p)
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": identity.User.ID, "email": identity.User.Email, "permissions": perms})
}

func (h *Handler) handleAPILogout(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	c, err := r.Cookie(sessionCookieName)
	if err == nil && c.Value != "" {
		_ = h.service.LogoutSession(r.Context(), c.Value)
		h.clearSessionCookie(w)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) handleAPIListEntityTypes(w http.ResponseWriter, r *http.Request) {
	items, err := h.service.ListEntityTypes(r.Context(), r.URL.Query().Get("q"), 500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

type apiCreateEntityTypeRequest struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (h *Handler) handleAPICreateEntityType(w http.ResponseWriter, r *http.Request) {
	var req apiCreateEntityTypeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid payload"})
		return
	}
	v, err := h.service.CreateEntityType(r.Context(), req.Key, req.Name, req.Description)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	h.writeAudit(r.Context(), "catalog.entity_type.create", "entity_type", &v.ID)
	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) handleAPIListRelationTypes(w http.ResponseWriter, r *http.Request) {
	items, err := h.service.ListRelationTypes(r.Context(), r.URL.Query().Get("q"), 500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

type apiCreateRelationTypeRequest struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Directed    bool   `json:"directed"`
}

func (h *Handler) handleAPICreateRelationType(w http.ResponseWriter, r *http.Request) {
	var req apiCreateRelationTypeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid payload"})
		return
	}
	v, err := h.service.CreateRelationType(r.Context(), req.Key, req.Name, req.Description, req.Directed)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	h.writeAudit(r.Context(), "catalog.relation_type.create", "relation_type", &v.ID)
	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) handleAPIListAttributeDefs(w http.ResponseWriter, r *http.Request) {
	items, err := h.service.ListAttributeDefs(r.Context(), r.URL.Query().Get("scope"), r.URL.Query().Get("q"), 500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

type apiUpsertAttributeDefRequest struct {
	Scope       string `json:"scope"`
	Key         string `json:"key"`
	ValueKind   string `json:"value_kind"`
	Description string `json:"description"`
}

func (h *Handler) handleAPIUpsertAttributeDef(w http.ResponseWriter, r *http.Request) {
	var req apiUpsertAttributeDefRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid payload"})
		return
	}
	v, err := h.service.UpsertAttributeDef(r.Context(), req.Scope, req.Key, req.ValueKind, req.Description)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	h.writeAudit(r.Context(), "catalog.attribute_def.upsert", "attribute_def", &v.ID)
	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) handleAPIListUsers(w http.ResponseWriter, r *http.Request) {
	items, err := h.service.ListUsers(r.Context(), r.URL.Query().Get("q"), 500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

type apiCreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	RoleID   uint   `json:"role_id"`
}

func (h *Handler) handleAPICreateUser(w http.ResponseWriter, r *http.Request) {
	var req apiCreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid payload"})
		return
	}
	v, err := h.service.CreateUser(r.Context(), req.Email, req.Password, req.RoleID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	h.writeAudit(r.Context(), "access.user.create", "user", &v.ID)
	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) handleAPIListRoles(w http.ResponseWriter, r *http.Request) {
	items, err := h.service.ListRoles(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

type apiAssignRoleRequest struct {
	UserID uint `json:"user_id"`
	RoleID uint `json:"role_id"`
}

func (h *Handler) handleAPIAssignRole(w http.ResponseWriter, r *http.Request) {
	var req apiAssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid payload"})
		return
	}
	if err := h.service.AssignRole(r.Context(), req.UserID, req.RoleID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	h.writeAudit(r.Context(), "access.role.assign", "user", &req.UserID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) handleAPIListAuditLogs(w http.ResponseWriter, r *http.Request) {
	items, err := h.service.ListAuditLogs(r.Context(), 500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (h *Handler) handleAPIListEntities(w http.ResponseWriter, r *http.Request) {
	var typeID *uint
	if raw := strings.TrimSpace(r.URL.Query().Get("type_id")); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid type_id"})
			return
		}
		v := uint(parsed)
		typeID = &v
	}
	list, err := h.service.ListEntities(r.Context(), typeID, r.URL.Query().Get("q"), 200)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, list)
}

type apiCreateEntityRequest struct {
	EntityTypeID uint   `json:"entity_type_id"`
	Name         string `json:"name"`
	Status       string `json:"status"`
}

func (h *Handler) handleAPICreateEntity(w http.ResponseWriter, r *http.Request) {
	var req apiCreateEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid payload"})
		return
	}
	v, err := h.service.CreateEntity(r.Context(), req.EntityTypeID, req.Name, req.Status)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	h.writeAudit(r.Context(), "graph.entity.create", "entity", &v.ID)
	writeJSON(w, http.StatusOK, v)
}

type apiCreateEdgeRequest struct {
	From       uint   `json:"from"`
	RelationID uint   `json:"relation_id"`
	To         uint   `json:"to"`
	Directed   bool   `json:"directed"`
	State      string `json:"state"`
}

func (h *Handler) handleAPICreateEdge(w http.ResponseWriter, r *http.Request) {
	var req apiCreateEdgeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid payload"})
		return
	}
	v, err := h.service.Connect(r.Context(), req.From, req.RelationID, req.To, req.Directed, req.State)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	h.writeAudit(r.Context(), "graph.edge.create", "edge", &v.ID)
	writeJSON(w, http.StatusOK, v)
}

type apiCutEdgeRequest struct {
	EdgeID uint `json:"edge_id"`
}

func (h *Handler) handleAPICutEdge(w http.ResponseWriter, r *http.Request) {
	var req apiCutEdgeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid payload"})
		return
	}
	v, err := h.service.CutEdge(r.Context(), req.EdgeID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	h.writeAudit(r.Context(), "graph.edge.cut", "edge", &v.ID)
	writeJSON(w, http.StatusOK, v)
}

type apiTraceRequest struct {
	StartEntityID  uint   `json:"start_entity_id"`
	TargetEntityID *uint  `json:"target_entity_id"`
	MaxDepth       int    `json:"max_depth"`
	RelationKeys   string `json:"relation_keys"`
}

type apiProvisionChainRequest struct {
	Nodes     string `json:"nodes"`
	Relations string `json:"relations"`
	Attrs     string `json:"attrs"`
	State     string `json:"state"`
}

func (h *Handler) handleAPIProvisionChain(w http.ResponseWriter, r *http.Request) {
	var req apiProvisionChainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid payload"})
		return
	}
	nodes, err := parseChainNodes(req.Nodes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	rels, err := parseChainRelations(req.Relations)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	out, err := h.service.ProvisionChain(r.Context(), application.ProvisionChainInput{
		Nodes:      nodes,
		Edges:      rels,
		Attributes: parseEntityAttrs(req.Attrs),
		State:      req.State,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	var targetID *uint
	if len(out.EntityIDs) > 0 {
		targetID = &out.EntityIDs[0]
	}
	h.writeAudit(r.Context(), "workflow.provision.chain", "entity", targetID)
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) handleAPITrace(w http.ResponseWriter, r *http.Request) {
	var req apiTraceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid payload"})
		return
	}
	hops, err := h.service.Trace(r.Context(), domain.TraceQuery{
		StartEntityID:  req.StartEntityID,
		TargetEntityID: req.TargetEntityID,
		MaxDepth:       req.MaxDepth,
		RelationKeys:   splitCSV(req.RelationKeys),
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if identity, ok := identityFromContext(r.Context()); ok {
		_ = h.service.SaveTraceRun(r.Context(), &identity.User.ID, domain.TraceQuery{
			StartEntityID:  req.StartEntityID,
			TargetEntityID: req.TargetEntityID,
			MaxDepth:       req.MaxDepth,
			RelationKeys:   splitCSV(req.RelationKeys),
		}, len(hops))
	}
	writeJSON(w, http.StatusOK, hops)
}

func readTraceSignals(r *http.Request) (domain.TraceQuery, error) {
	var sig traceSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		return domain.TraceQuery{}, fmt.Errorf("invalid signals")
	}
	q := domain.TraceQuery{
		MaxDepth:     sig.TraceMaxDepth,
		RelationKeys: splitCSV(sig.TraceRelationKeys),
	}
	startID, err := parseRequiredUintSignal(sig.TraceStartEntityID, "traceStartEntityId")
	if err != nil {
		return domain.TraceQuery{}, err
	}
	q.StartEntityID = startID
	if strings.TrimSpace(sig.TraceTargetEntityID) != "" {
		parsed, err := strconv.ParseUint(strings.TrimSpace(sig.TraceTargetEntityID), 10, 64)
		if err != nil {
			return domain.TraceQuery{}, fmt.Errorf("traceTargetEntityId must be an integer")
		}
		value := uint(parsed)
		q.TargetEntityID = &value
	}
	return q, nil
}

func parseRequiredUintSignal(raw string, field string) (uint, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, fmt.Errorf("%s is required", field)
	}
	parsed, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", field)
	}
	return uint(parsed), nil
}

func parseOptionalUintSignal(raw string, field string) (*uint, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%s must be an integer", field)
	}
	v := uint(parsed)
	return &v, nil
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

func parseChainNodes(input string) ([]application.ProvisionChainNode, error) {
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
		nodes = append(nodes, application.ProvisionChainNode{
			TypeKey:    strings.TrimSpace(kv[0]),
			EntityName: strings.TrimSpace(kv[1]),
		})
	}
	if len(nodes) < 2 {
		return nil, fmt.Errorf("at least two nodes are required")
	}
	return nodes, nil
}

func parseChainRelations(input string) ([]application.ProvisionChainEdge, error) {
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

func parseEntityAttrs(input string) map[string]map[string]string {
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
		attrPairs := strings.Split(parts[1], ",")
		if _, ok := out[entityName]; !ok {
			out[entityName] = make(map[string]string)
		}
		for _, attrPair := range attrPairs {
			kv := strings.SplitN(strings.TrimSpace(attrPair), "=", 2)
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

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (h *Handler) writeAudit(ctx context.Context, action, targetType string, targetID *uint) {
	identity, ok := identityFromContext(ctx)
	if !ok {
		h.service.WriteAudit(ctx, nil, action, targetType, targetID, "")
		return
	}
	h.service.WriteAudit(ctx, &identity.User.ID, action, targetType, targetID, "")
}

func pagePathFromReferer(r *http.Request) string {
	referer := strings.TrimSpace(r.Referer())
	if referer == "" {
		return ""
	}
	parsed, err := url.Parse(referer)
	if err != nil {
		return ""
	}
	return parsed.Path
}

func renderHTMLFragments(ctx context.Context, w http.ResponseWriter, status int, fragments ...templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	for _, fragment := range fragments {
		if fragment == nil {
			continue
		}
		_ = fragment.Render(ctx, w)
	}
}

func (h *Handler) renderFlash(ctx context.Context, w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if status >= 400 {
		_ = ui.Flash(message, "error").Render(ctx, w)
		return
	}
	_ = ui.Flash(message, "info").Render(ctx, w)
}
