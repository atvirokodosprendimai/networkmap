# UI/UX Refactoring Specification

## User story

As a network operator with no programming knowledge, I want a GUI that guides me step-by-step through creating types, objects, and connections, shows me instant feedback after every action, and prevents me from making mistakes, so that I never have to guess where to click or wonder if my action succeeded.

## Current state (problems)

The analysis below was produced by reading every template (`internal/ui/`), every HTTP handler (`internal/adapters/http/router.go`), and mapping every Datastar action, signal, and DOM fragment target.

### Security

- Admin Access password input has no `type="password"` -- password is visible as typed.
- Password value stored in Datastar signal (plain text in DOM/JS memory).

### Accessibility

- Zero `<label>` elements in the entire app; all inputs use placeholder-only labels.
- No `aria-*` attributes beyond one `role="alert"` on flash messages.

### Feedback

- All 12 mutation handlers return only a `#flash` div. No table, dropdown, or counter updates after create/edit operations.
- User must manually reload page (or click "Refresh wizard state") to see new data.
- No loading/spinner state on any submit button -- double-submit risk.
- No confirmation dialog before destructive operations (Cut).

### Flowbite

- Flowbite CSS + JS are loaded (4.0.1 CDN) but zero Flowbite components are instantiated. The imports are dead weight until we use them.

### Datastar

- ContentType inconsistency: same endpoint called with `{contentType: 'form'}` from Wizard but default JSON from Admin Catalog.
- No `data-indicator` usage anywhere (loading states).
- No `@get` actions used -- even reads use `@post`.

### Navigation

- No mobile hamburger toggle -- sidebar takes full width on small screens.
- No logged-in user display.
- Nav labels too long ("Catalog: Object + Connection Types").

### Data display

- Raw numeric IDs shown in dropdowns, previews, trace history, and tables where human names should appear.
- No pagination on any table.
- No sorting or filtering on audit logs.

---

## Phases

### Phase 1 -- Security & Accessibility Fixes

#### Acceptance criteria

- [ ] Admin Access: password input has `type="password"`.
- [ ] All text/select/checkbox inputs have an associated `<label>` element with `for` attribute matching input `id`.
- [ ] Flowbite floating-label pattern used where appropriate.
- [ ] All Datastar `@post` actions use consistent contentType (remove `{contentType: 'form'}` everywhere; use default JSON transport with `datastar.ReadSignals` on backend).
- [ ] Login form retains traditional `<form method="POST">` (not Datastar) since it must work without JS hydration.

#### Non-goals

- No new features. Only fix what is broken or insecure.

#### Edge cases

- Login page must work even if Datastar JS fails to load (progressive enhancement).
- Password field must not be pre-filled by browser autocomplete for the admin create-user form (use `autocomplete="new-password"`).
- Floating labels must not overlap placeholder text on page load.

#### Files to touch

| File | Changes |
|------|---------|
| `internal/ui/login.templ` | Add `<label>` elements, add `id` to inputs. |
| `internal/ui/app.templ` | Add `<label>` + `id` to all inputs. Add `type="password"` + `autocomplete="new-password"` to admin password field. Remove `{contentType: 'form'}` from all `@post` actions. |

#### Verification

```bash
templ generate && go test ./...
# Manual: open /admin/access, verify password field is masked
# Manual: open /wizard, verify all inputs have visible labels
# Manual: inspect DOM for <label for="..."> on every input
```

---

### Phase 2 -- Multi-Fragment Auto-Refresh After Mutations

#### Acceptance criteria

- [ ] After creating an entity type (from Wizard or Catalog), the entity types table on the current page updates without reload, AND any entity-type `<select>` dropdown refreshes to include the new type.
- [ ] After creating a relation type, relation types table and `<select>` dropdowns refresh.
- [ ] After creating an entity, inventory table and entity `<select>` dropdowns refresh.
- [ ] After creating an edge (connect/splice), edge dropdown in Cut form and quick-fill buttons refresh.
- [ ] After cutting an edge, edge dropdown updates to reflect new "cut" state.
- [ ] After upserting an attribute def, attribute defs table refreshes.
- [ ] After creating a user, users table and assign-role user dropdown refresh.
- [ ] After assigning a role, flash confirms success (no additional table change needed yet).
- [ ] Wizard status counters (object types / connection types / objects) update after each step without manual page reload.
- [ ] "Refresh wizard state" button removed from Wizard page.
- [ ] Flash message still appears for every mutation (success or error).

#### Non-goals

- No SSE/WebSocket push. Responses are synchronous multi-fragment HTML from the same POST handler.
- No optimistic UI updates. Server is source of truth.

#### Architecture

Each mutation handler changes from:

```go
// before
h.renderFlash(ctx, w, 200, "Created entity type #1")
```

To rendering multiple fragments:

```go
// after
w.Header().Set("Content-Type", "text/html; charset=utf-8")
_ = ui.Flash("Created entity type #1", "info").Render(ctx, w)
_ = ui.EntityTypesTable(updatedTypes).Render(ctx, w)
_ = ui.WizardEntityTypeSelect(updatedTypes).Render(ctx, w)
_ = ui.WizardStatusBar(len(types), len(rels), len(entities)).Render(ctx, w)
```

Datastar will morph each top-level element by its `id` attribute. Each fragment template must have a stable root `id`.

#### New templ components needed

| Component | Root `id` | Purpose |
|-----------|-----------|---------|
| `WizardStatusBar(typeCount, relCount, entityCount int)` | `wizard-status` | The 3 counter cards at top of wizard |
| `WizardEntityTypeSelect(types)` | `wizard-entity-type-select` | Step 3 type dropdown |
| `WizardRelationTypeSelect(rels)` | `wizard-relation-select` | Step 4 relation dropdown |
| `WizardEntitySelectA(entities)` | `wizard-entity-select-a` | Step 4 "from" dropdown |
| `WizardEntitySelectB(entities)` | `wizard-entity-select-b` | Step 4 "to" dropdown |
| `WizardStep2Lock(hasTypes bool)` | `wizard-step2-lock` | Lock/unlock indicator for step 2 |
| `WizardStep3Lock(hasTypes bool)` | `wizard-step3-lock` | Lock/unlock indicator for step 3 |
| `WizardStep4Lock(hasRels bool, entityCount int)` | `wizard-step4-lock` | Lock/unlock indicator for step 4 |

#### Edge cases

- Creating an entity type from `/admin/catalog` should refresh the catalog table but NOT try to render wizard fragments (different page context). Handler must detect which page the request came from (via `Referer` header or a signal like `_page`).
- If `<select>` has a currently selected value and the list refreshes, the selection should be preserved (Datastar morph preserves `value` on matching `<option>`, but test this).
- Error responses should still return only `#flash` (no stale fragments).

#### Files to touch

| File | Changes |
|------|---------|
| `internal/ui/app.templ` | Extract wizard sub-fragments with stable `id`s. Add `id` to existing tables (EntityTypesTable, etc.). Remove "Refresh wizard state" link. |
| `internal/adapters/http/router.go` | Modify all 12 mutation handlers to render multi-fragment responses. Add helper to detect source page. Re-query updated data after mutation. |

#### Verification

```bash
templ generate && go test ./...
# Manual: open /wizard, create entity type, verify:
#   - flash shows success
#   - status counter increments
#   - step 3 dropdown shows new type
#   - step 2 lock disappears
# Manual: open /admin/catalog, create entity type, verify:
#   - flash shows success
#   - entity types table updates
# Manual: create 2 entities, verify step 4 unlocks automatically
```

---

### Phase 3 -- Wizard Improvements (Stepper, Validation, Loading, Collapse)

#### Acceptance criteria

- [ ] Flowbite stepper component at top of wizard shows 4 steps as circles connected by lines. Completed steps = green, current = blue, locked = gray.
- [ ] Completed steps are collapsible (Flowbite accordion). Collapsed state shows summary: "3 object types created".
- [ ] All required inputs have `required` attribute and Flowbite validation error styling on invalid.
- [ ] All submit buttons show a spinner and become disabled while request is in flight (via `data-indicator`).
- [ ] Wizard step 4 prevents selecting the same object as both A and B (client-side check: `data-attr:disabled="$edgeSubjectId !== '' && $edgeSubjectId === $edgeObjectId"` on submit button, plus visual warning).

#### Non-goals

- No client-side-only step advancement (server is source of truth for step completion).
- No drag-and-drop reordering of steps.

#### Edge cases

- If a user arrives at `/wizard` with all steps already complete, all steps should show as completed/collapsed with a "You're all set!" message.
- Accordion collapse/expand must not interfere with Datastar signal bindings inside the form.
- Loading indicator must clear even if the server returns an error response.
- Browser back/forward should not break accordion state (use `data-preserve-attr="open"` on `<details>`).

#### Flowbite components to use

| Component | Where | Data attributes |
|-----------|-------|-----------------|
| Stepper (ol/li) | Top of wizard page | CSS-only (no JS data attrs needed) |
| Accordion | Each step form | `data-accordion="collapse"` on container, `data-accordion-target` on triggers |
| Spinner | Inside submit buttons | Flowbite spinner SVG inside `<span data-show="$_submitting">` |

#### Files to touch

| File | Changes |
|------|---------|
| `internal/ui/app.templ` | Add stepper markup, wrap step forms in accordion, add `required` attrs, add `data-indicator` + spinner to buttons, add same-object guard on step 4. |

#### Verification

```bash
templ generate && go test ./...
# Manual: open /wizard with empty DB
#   - Steps 2-4 locked (gray in stepper, buttons disabled)
#   - Step 1 form has visible labels, required validation
# Manual: submit step 1 with empty key field
#   - Browser shows validation error, form does not submit
# Manual: submit step 1 with valid data
#   - Button shows spinner during request
#   - On success: step 1 collapses, stepper shows step 1 green
#   - Step 2 unlocks
# Manual: complete all 4 steps
#   - Stepper shows all 4 green, "You're all set!" message appears
# Manual: in step 4, select same object for A and B
#   - Submit button disabled, warning text shown
```

---

### Phase 4 -- Sidebar & Navigation

#### Acceptance criteria

- [ ] On mobile (`< lg` breakpoint), sidebar is hidden by default. A hamburger icon in a top bar toggles a Flowbite drawer/offcanvas overlay.
- [ ] On desktop (`>= lg`), sidebar is always visible (current behavior, no change).
- [ ] Current user email shown at bottom of sidebar above logout button.
- [ ] Nav links grouped under section headings: "Operations" and "Admin".
- [ ] Labels shortened: "Wizard", "Catalog", "Access", "Audit".
- [ ] Active nav link has a left border accent (in addition to current background color).

#### Non-goals

- No dark mode toggle.
- No collapsible sidebar on desktop.

#### Edge cases

- Drawer must close when a nav link is clicked (use Flowbite `data-drawer-hide` on link click).
- Drawer backdrop must prevent interaction with content behind it.
- If user email is very long, truncate with `truncate` class.

#### Flowbite components to use

| Component | Where | Data attributes |
|-----------|-------|-----------------|
| Drawer | Mobile sidebar | `data-drawer-target`, `data-drawer-toggle`, `data-drawer-hide` |
| Drawer backdrop | Behind drawer | Flowbite handles automatically |

#### Files to touch

| File | Changes |
|------|---------|
| `internal/ui/app.templ` | Refactor `AppLayout`: add top bar with hamburger for mobile, wrap sidebar in drawer markup, pass user email, add section headings, shorten labels. |
| `internal/adapters/http/router.go` | Pass `identity.User.Email` to page render functions (already available via context). |

#### Verification

```bash
templ generate && go test ./...
# Manual: open any page at mobile width (< 1024px)
#   - Sidebar hidden, hamburger icon visible in top bar
#   - Click hamburger -> sidebar slides in as overlay
#   - Click a nav link -> sidebar closes, page navigates
# Manual: open at desktop width
#   - Sidebar always visible, no hamburger
# Manual: verify user email shown above logout button
```

---

### Phase 5 -- Workflows Page (Tabs, Confirmation Modal, Toasts)

#### Acceptance criteria

- [ ] Connect, Cut, and Splice forms are in Flowbite tabs (only one visible at a time).
- [ ] URL hash controls active tab: `/workflows#connect`, `/workflows#cut`, `/workflows#splice`.
- [ ] Dashboard action cards linking to `/workflows#cut` correctly activate the Cut tab on load.
- [ ] Before executing "Mark as cut", a Flowbite modal appears with edge details and "Are you sure?" / "Cancel" buttons.
- [ ] All mutation success/error messages appear as Flowbite toast notifications (top-right, auto-dismiss after 5 seconds) instead of inline `#flash`.
- [ ] Toast template returned from server as a fragment; Datastar morphs it into a `#toast-container` div.

#### Non-goals

- No undo/restore workflow for cut edges (future feature).
- No WebSocket-based real-time edge status updates.

#### Edge cases

- If user navigates to `/workflows` with no hash, default to Connect tab.
- If user navigates to `/workflows#cut` and there are no edges, show "No edges to cut" message inside the tab.
- Modal must be keyboard-dismissable (Esc key) and trap focus.
- Toast must stack if multiple toasts appear quickly.
- Tab switch must not lose form input values (Datastar signals persist across tab visibility changes since all forms are in the DOM).

#### Flowbite components to use

| Component | Where | Data attributes |
|-----------|-------|-----------------|
| Tabs | Workflow form container | `data-tabs-toggle` on `<ul>`, `role="tablist"` |
| Modal | Cut confirmation | `data-modal-target`, `data-modal-toggle`, `data-modal-hide` |
| Toast | Success/error notifications | Positioned `fixed top-4 right-4`, with dismiss timer |

#### New templ components needed

| Component | Root `id` | Purpose |
|-----------|-----------|---------|
| `Toast(message, level string)` | `toast-container` (appended) | Success/error toast notification |
| `CutConfirmModal(edge EdgeSummary, impacted int)` | `cut-confirm-modal` | Confirmation dialog before cut |

#### Files to touch

| File | Changes |
|------|---------|
| `internal/ui/app.templ` | Refactor `WorkflowsPage` into tabs. Add modal markup for cut confirmation. Add toast template. Add `#toast-container` to `AppLayout`. |
| `internal/adapters/http/router.go` | `handleWorkflowCut`: change to two-step flow (preview populates modal, confirm executes). Mutation handlers return Toast fragment instead of Flash where appropriate. |

#### Verification

```bash
templ generate && go test ./...
# Manual: open /workflows -> Connect tab active by default
# Manual: open /workflows#cut -> Cut tab active
# Manual: select an edge, click "Mark as cut"
#   - Modal appears with edge details
#   - Click Cancel -> modal closes, nothing happens
#   - Click Confirm -> modal closes, toast appears "Edge #N marked as cut"
# Manual: create a connection -> toast appears "Created edge #N"
# Manual: toast auto-dismisses after ~5 seconds
```

---

### Phase 6 -- Tables & Data Display

#### Acceptance criteria

- [ ] All `<select>` option labels show human-readable names without raw numeric IDs. Format: `"ONU-12-Flat-4 (Customer ONU)"` instead of `"#3 - ONU-12-Flat-4 (type 1)"`.
- [ ] Inventory table shows "Type" column with type name instead of numeric type ID.
- [ ] Trace history shows entity name: `"Start: ONU-12-Flat-4, 5 hops"` instead of `"Start 42, hops 5"`.
- [ ] Cut preview shows entity names: `"ONU-12-Flat-4 -> Splitter-A"` instead of `"17 -> 23"`.
- [ ] Inventory results have Flowbite pagination (20 items per page, server-side).
- [ ] Audit logs have Flowbite pagination (50 items per page, server-side).
- [ ] Audit log page has a search bar filtering by actor email and action type.
- [ ] Trace history has Flowbite pagination (10 items per page).

#### Non-goals

- No client-side sorting (server-side only if added later).
- No inline edit/delete on table rows (future feature).
- No CSV/JSON export (future feature).

#### Edge cases

- Pagination must preserve search/filter state in query params.
- Empty pages (page > total) should redirect to last valid page.
- Entity with a deleted/missing type should show "Unknown type" instead of crashing.
- Audit log search with no results should show "No matching records" message.

#### Data model changes needed

- `TraceRun` needs a `StartEntityName` field (join in query or populate in service layer).
- `InventoryResults` needs entity type name (pass `[]EntityType` or pre-join).
- `ObjectOptions` templ needs type name per entity (pass a map or enriched struct).

#### Files to touch

| File | Changes |
|------|---------|
| `internal/domain/model.go` | Add `StartEntityName` to `TraceRun`. Add `EntityTypeName` to `Entity` (or create a view struct). |
| `internal/domain/ports.go` | Add pagination params (`offset`, `limit`) to list methods. Add `ListAuditLogs` filter params. |
| `internal/application/service.go` | Thread pagination and filter params. Populate entity type names. |
| `internal/adapters/db/sqlite/repository.go` | Add JOIN for entity type name in entity list queries. Add pagination. Add audit log filtering. |
| `internal/ui/app.templ` | Update `ObjectOptions`, `TraceHistory`, `CutPreview`, `InventoryResults` to show names. Add pagination component. Add audit search bar. |
| `internal/adapters/http/router.go` | Parse `page` query param, pass to service, pass pagination info to templates. |

#### Verification

```bash
templ generate && go test ./...
# Manual: open /inventory with > 20 objects
#   - Only 20 shown, pagination controls visible
#   - Click page 2 -> next 20 shown
#   - Type column shows "Customer ONU" not "1"
# Manual: open /admin/audit with > 50 logs
#   - Pagination visible
#   - Type "admin" in search -> filters by actor email
# Manual: open /map -> trace history shows entity names
# Manual: open /workflows -> cut preview shows entity names
# Manual: all dropdowns show "ONU-12-Flat-4 (Customer ONU)" format
```

---

### Phase 7 -- Dashboard Improvements

#### Acceptance criteria

- [ ] Dashboard shows 4 stat cards: Objects count, Connection Types count, Links count, Traces today count.
- [ ] Each stat card is color-coded: green if > 0, amber if 0.
- [ ] Dashboard shows "Recent Activity" section: last 5 audit log entries as a Flowbite timeline.
- [ ] Each timeline entry shows: actor email, action (as badge), target description, relative timestamp ("2 minutes ago").
- [ ] "Daily Operator Checklist" section removed (replaced by recent activity).
- [ ] Action cards remain but reordered: Wizard first, then Map, Workflows, Inventory.

#### Non-goals

- No real-time auto-refresh on dashboard (manual page load is fine).
- No charts or graphs.

#### Edge cases

- "Traces today" should use server timezone (or UTC) consistently.
- If there are no audit entries, show "No recent activity" placeholder.
- Relative timestamps should not show "0 seconds ago" -- show "just now" instead.

#### Files to touch

| File | Changes |
|------|---------|
| `internal/ui/app.templ` | Rewrite `DashboardPage` to accept stats and recent activity data. Add stat cards and timeline component. Remove checklist. |
| `internal/adapters/http/router.go` | `handleDashboard`: query counts (entities, relation types, edges, today's traces) and recent audit logs. Pass to template. |
| `internal/application/service.go` | Add `CountEntities`, `CountEdges`, `CountTodayTraces` methods (or a single `DashboardStats` method). |
| `internal/adapters/db/sqlite/repository.go` | Add count queries. |
| `internal/domain/ports.go` | Add count methods to repository interface. |

#### Verification

```bash
templ generate && go test ./...
# Manual: open /dashboard with data in DB
#   - 4 stat cards showing correct counts
#   - Recent activity timeline with last 5 entries
#   - Action cards visible with Wizard first
# Manual: open /dashboard with empty DB
#   - Stat cards show 0 with amber indicators
#   - "No recent activity" placeholder shown
```

---

## Implementation order

| Priority | Phase | Effort estimate | Key risk |
|----------|-------|-----------------|----------|
| 1 | Phase 1: Security & accessibility | S | Low -- mechanical changes |
| 2 | Phase 2: Auto-refresh mutations | M | Medium -- multi-fragment response pattern new to codebase |
| 3 | Phase 3: Wizard stepper/validation | M | Low -- mostly template work |
| 4 | Phase 5.2: Cut confirmation modal | S | Low -- single Flowbite component |
| 5 | Phase 4: Mobile sidebar | S | Low -- Flowbite drawer |
| 6 | Phase 6.1: Human-readable names | M | Medium -- requires data model/query changes |
| 7 | Phase 5.1: Workflow tabs | S | Low -- Flowbite tabs |
| 8 | Phase 5.3: Toast notifications | S | Low -- template + handler change |
| 9 | Phase 4 remainder: Nav grouping + user | S | Low |
| 10 | Phase 6.2-6.3: Pagination + audit filter | M | Medium -- pagination threading |
| 11 | Phase 7: Dashboard stats + activity | M | Low -- new queries + template |

## Global constraints

- **Language/runtime:** Go 1.21+, templ v0.3.x, Datastar RC.7, Flowbite 4.0.1 CDN.
- **CSS:** Tailwind via CDN (acceptable for internal tool; no build step).
- **Architecture:** Hexagonal -- domain/application/adapters. No domain logic in handlers or templates.
- **Testing:** `go test ./...` must pass after every phase. Manual browser verification for UI.
- **Security:** No credentials in Datastar signals. Password fields always `type="password"`. Session cookie `HttpOnly`.

## Verification commands (run after every phase)

```bash
# 1. Generate templ
templ generate

# 2. Build
go build ./cmd/app

# 3. Test
go test ./...

# 4. Run server for manual testing
go run ./cmd/app
# Then open http://localhost:8080
```
