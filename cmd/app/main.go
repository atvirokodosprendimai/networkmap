package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	sqliteadapter "github.com/atvirokodosprendimai/networkmap/internal/adapters/db/sqlite"
	httpadapter "github.com/atvirokodosprendimai/networkmap/internal/adapters/http"
	rpcadapter "github.com/atvirokodosprendimai/networkmap/internal/adapters/rpcjson"
	"github.com/atvirokodosprendimai/networkmap/internal/application"
	"github.com/atvirokodosprendimai/networkmap/internal/domain"
	"github.com/urfave/cli/v3"
)

func main() {
	args := os.Args
	if len(args) == 1 {
		args = append(args, "--help")
	}

	root := &cli.Command{
		Name:  "networkmap",
		Usage: "Network mapping system server and CLI",
		Commands: []*cli.Command{
			serverCommand(),
			authCommand(),
			objectsCommand(),
			edgesCommand(),
			traceCommand(),
			catalogCommand(),
			accessCommand(),
			auditCommand(),
			workflowCommand(),
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runServer(ctx, ":8080", "/tmp/networkmap.sock", "networkmap.db", "admin@networkmap.local", "admin")
		},
	}

	if err := root.Run(context.Background(), args); err != nil {
		log.Fatal(err)
	}
}

func workflowCommand() *cli.Command {
	return &cli.Command{
		Name:  "workflow",
		Usage: "Operator workflow helpers",
		Commands: []*cli.Command{
			{
				Name:  "provision-chain",
				Usage: "Provision any chain using type:name node specs",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "nodes", Required: true, Usage: "type_key:EntityName,type_key:EntityName"},
					&cli.StringFlag{Name: "relations", Required: true, Usage: "relation_key,relation_key"},
					&cli.StringFlag{Name: "attrs", Usage: "EntityName:key=value,key=value;EntityName:key=value"},
					&cli.StringFlag{Name: "state", Value: "active"},
					&cli.BoolFlag{Name: "json", Usage: "output raw JSON"},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					cfg, err := loadConfig()
					if err != nil {
						return err
					}
					in := map[string]any{
						"nodes":     c.String("nodes"),
						"relations": c.String("relations"),
						"attrs":     c.String("attrs"),
						"state":     c.String("state"),
					}
					var out application.ProvisionChainResult
					if err := doWorkflowProvisionChain(ctx, cfg, in, &out); err != nil {
						return err
					}
					if c.Bool("json") {
						return printJSON(out)
					}
					printChainProvisionResult(out)
					return nil
				},
			},
		},
	}
}

func serverCommand() *cli.Command {
	return &cli.Command{
		Name:  "server",
		Usage: "Run HTTP server",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "addr", Value: ":8080", Usage: "HTTP listen address"},
			&cli.StringFlag{Name: "rpc-socket", Value: "/tmp/networkmap.sock", Usage: "JSON-RPC unix socket path"},
			&cli.StringFlag{Name: "db-path", Value: "networkmap.db", Usage: "SQLite database path"},
			&cli.StringFlag{Name: "bootstrap-admin-email", Value: "admin@networkmap.local", Usage: "initial admin email"},
			&cli.StringFlag{Name: "bootstrap-admin-password", Value: "admin", Usage: "initial admin password when users are empty"},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			return runServer(ctx, c.String("addr"), c.String("rpc-socket"), c.String("db-path"), c.String("bootstrap-admin-email"), c.String("bootstrap-admin-password"))
		},
	}
}

func runServer(ctx context.Context, addr, rpcSocket, dbPath, bootstrapEmail, bootstrapPassword string) error {
	db, err := sqliteadapter.Open(dbPath)
	if err != nil {
		return err
	}
	if err := sqliteadapter.RunMigrations(ctx, db); err != nil {
		return err
	}

	repo := sqliteadapter.NewGraphRepository(db)
	service := application.NewGraphService(repo)
	if err := service.BootstrapAdmin(ctx, bootstrapEmail, bootstrapPassword); err != nil {
		return err
	}

	router := httpadapter.NewRouter(service)
	srv := &http.Server{Addr: addr, Handler: router, ReadHeaderTimeout: 5 * time.Second}
	rpcSrv, err := rpcadapter.Start(rpcSocket, service)
	if err != nil {
		return err
	}

	defer func() {
		_ = rpcSrv.Close()
	}()
	log.Printf("json-rpc listening on unix://%s", rpcSocket)

	errCh := make(chan error, 1)
	go func() {
		log.Printf("server listening on %s", srv.Addr)
		errCh <- srv.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("received signal %s, shutting down", sig)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func authCommand() *cli.Command {
	return &cli.Command{
		Name:  "auth",
		Usage: "Authentication commands",
		Commands: []*cli.Command{
			{
				Name:  "login",
				Usage: "Login and store CLI token",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "transport", Value: "uds"},
					&cli.StringFlag{Name: "server", Value: "http://127.0.0.1:8080"},
					&cli.StringFlag{Name: "socket", Value: "/tmp/networkmap.sock"},
					&cli.StringFlag{Name: "email", Required: true},
					&cli.StringFlag{Name: "password", Required: true},
					&cli.StringFlag{Name: "token-name", Value: "cli"},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					cfg := cliConfig{Transport: c.String("transport"), Server: c.String("server"), Socket: c.String("socket")}
					var out struct {
						Token string `json:"token"`
						Email string `json:"email"`
					}
					err := doLogin(ctx, cfg, c.String("email"), c.String("password"), c.String("token-name"), &out)
					if err != nil {
						return err
					}
					cfg.Token = out.Token
					if err := saveConfig(cfg); err != nil {
						return err
					}
					fmt.Printf("logged in as %s\n", out.Email)
					return nil
				},
			},
			{
				Name:  "whoami",
				Usage: "Show current authenticated user",
				Flags: []cli.Flag{&cli.BoolFlag{Name: "json", Usage: "output raw JSON"}},
				Action: func(ctx context.Context, c *cli.Command) error {
					cfg, err := loadConfig()
					if err != nil {
						return err
					}
					var out struct {
						ID    uint   `json:"id"`
						Email string `json:"email"`
					}
					if err := doWhoAmI(ctx, cfg, &out); err != nil {
						return err
					}
					if c.Bool("json") {
						return printJSON(out)
					}
					printKV([][2]string{{"id", uintToString(out.ID)}, {"email", out.Email}})
					return nil
				},
			},
			{
				Name:  "logout",
				Usage: "Clear local CLI auth token",
				Action: func(ctx context.Context, c *cli.Command) error {
					cfg, err := loadConfig()
					if err != nil {
						return err
					}
					_ = doLogout(ctx, cfg)
					cfg.Token = ""
					if err := saveConfig(cfg); err != nil {
						return err
					}
					fmt.Println("logged out")
					return nil
				},
			},
		},
	}
}

func objectsCommand() *cli.Command {
	return &cli.Command{
		Name:  "objects",
		Usage: "Object commands",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List objects",
				Flags: []cli.Flag{
					&cli.UintFlag{Name: "type-id"},
					&cli.StringFlag{Name: "q"},
					&cli.BoolFlag{Name: "json", Usage: "output raw JSON"},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					cfg, err := loadConfig()
					if err != nil {
						return err
					}
					var typeID *uint
					if c.IsSet("type-id") {
						v := c.Uint("type-id")
						typeID = &v
					}
					var out []domain.Entity
					if err := doObjectsList(ctx, cfg, typeID, c.String("q"), &out); err != nil {
						return err
					}
					if c.Bool("json") {
						return printJSON(out)
					}
					printEntities(out)
					return nil
				},
			},
			{
				Name:  "create",
				Usage: "Create object",
				Flags: []cli.Flag{
					&cli.UintFlag{Name: "type-id", Required: true},
					&cli.StringFlag{Name: "name", Required: true},
					&cli.StringFlag{Name: "status", Value: "active"},
					&cli.BoolFlag{Name: "json", Usage: "output raw JSON"},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					cfg, err := loadConfig()
					if err != nil {
						return err
					}
					var out domain.Entity
					err = doObjectsCreate(ctx, cfg, c.Uint("type-id"), c.String("name"), c.String("status"), &out)
					if err != nil {
						return err
					}
					if c.Bool("json") {
						return printJSON(out)
					}
					printKV([][2]string{{"id", uintToString(out.ID)}, {"type_id", uintToString(out.EntityTypeID)}, {"name", out.Name}, {"status", out.Status}})
					return nil
				},
			},
		},
	}
}

func edgesCommand() *cli.Command {
	return &cli.Command{
		Name:  "edges",
		Usage: "Edge commands",
		Commands: []*cli.Command{
			{
				Name:  "connect",
				Usage: "Connect two objects",
				Flags: []cli.Flag{
					&cli.UintFlag{Name: "from", Required: true},
					&cli.UintFlag{Name: "relation-id", Required: true},
					&cli.UintFlag{Name: "to", Required: true},
					&cli.BoolFlag{Name: "directed"},
					&cli.StringFlag{Name: "state", Value: "active"},
					&cli.BoolFlag{Name: "json", Usage: "output raw JSON"},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					cfg, err := loadConfig()
					if err != nil {
						return err
					}
					var out domain.EdgeSummary
					err = doEdgesConnect(ctx, cfg, c.Uint("from"), c.Uint("relation-id"), c.Uint("to"), c.Bool("directed"), c.String("state"), &out)
					if err != nil {
						return err
					}
					if c.Bool("json") {
						return printJSON(out)
					}
					printEdgeSummary(out)
					return nil
				},
			},
			{
				Name:  "cut",
				Usage: "Cut edge by id",
				Flags: []cli.Flag{&cli.UintFlag{Name: "edge-id", Required: true}, &cli.BoolFlag{Name: "json", Usage: "output raw JSON"}},
				Action: func(ctx context.Context, c *cli.Command) error {
					cfg, err := loadConfig()
					if err != nil {
						return err
					}
					var out domain.EdgeSummary
					err = doEdgesCut(ctx, cfg, c.Uint("edge-id"), &out)
					if err != nil {
						return err
					}
					if c.Bool("json") {
						return printJSON(out)
					}
					printEdgeSummary(out)
					return nil
				},
			},
		},
	}
}

func traceCommand() *cli.Command {
	return &cli.Command{
		Name:  "trace",
		Usage: "Trace graph path",
		Flags: []cli.Flag{
			&cli.UintFlag{Name: "from", Required: true},
			&cli.UintFlag{Name: "to"},
			&cli.IntFlag{Name: "depth", Value: 8},
			&cli.StringFlag{Name: "relations", Usage: "csv relation keys"},
			&cli.BoolFlag{Name: "json", Usage: "output raw JSON"},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			var targetID *uint
			if c.IsSet("to") {
				v := c.Uint("to")
				targetID = &v
			}
			var out []domain.TraversalHop
			if err := doTrace(ctx, cfg, c.Uint("from"), targetID, c.Int("depth"), c.String("relations"), &out); err != nil {
				return err
			}
			if c.Bool("json") {
				return printJSON(out)
			}
			printTraversal(out)
			return nil
		},
	}
}

func catalogCommand() *cli.Command {
	return &cli.Command{
		Name:  "catalog",
		Usage: "Catalog commands",
		Commands: []*cli.Command{
			{
				Name:  "entity-types",
				Usage: "Manage entity types",
				Commands: []*cli.Command{
					{
						Name:  "list",
						Usage: "List entity types",
						Flags: []cli.Flag{&cli.StringFlag{Name: "q"}, &cli.BoolFlag{Name: "json", Usage: "output raw JSON"}},
						Action: func(ctx context.Context, c *cli.Command) error {
							cfg, err := loadConfig()
							if err != nil {
								return err
							}
							var out []domain.EntityType
							if err := doEntityTypesList(ctx, cfg, c.String("q"), &out); err != nil {
								return err
							}
							if c.Bool("json") {
								return printJSON(out)
							}
							printEntityTypes(out)
							return nil
						},
					},
					{
						Name:  "create",
						Usage: "Create entity type",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "key", Required: true},
							&cli.StringFlag{Name: "name", Required: true},
							&cli.StringFlag{Name: "description"},
							&cli.BoolFlag{Name: "json", Usage: "output raw JSON"},
						},
						Action: func(ctx context.Context, c *cli.Command) error {
							cfg, err := loadConfig()
							if err != nil {
								return err
							}
							var out domain.EntityType
							if err := doEntityTypesCreate(ctx, cfg, c.String("key"), c.String("name"), c.String("description"), &out); err != nil {
								return err
							}
							if c.Bool("json") {
								return printJSON(out)
							}
							printEntityTypes([]domain.EntityType{out})
							return nil
						},
					},
				},
			},
			{
				Name:  "relation-types",
				Usage: "Manage relation types",
				Commands: []*cli.Command{
					{
						Name:  "list",
						Usage: "List relation types",
						Flags: []cli.Flag{&cli.StringFlag{Name: "q"}, &cli.BoolFlag{Name: "json", Usage: "output raw JSON"}},
						Action: func(ctx context.Context, c *cli.Command) error {
							cfg, err := loadConfig()
							if err != nil {
								return err
							}
							var out []domain.RelationType
							if err := doRelationTypesList(ctx, cfg, c.String("q"), &out); err != nil {
								return err
							}
							if c.Bool("json") {
								return printJSON(out)
							}
							printRelationTypes(out)
							return nil
						},
					},
					{
						Name:  "create",
						Usage: "Create relation type",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "key", Required: true},
							&cli.StringFlag{Name: "name", Required: true},
							&cli.StringFlag{Name: "description"},
							&cli.BoolFlag{Name: "directed"},
							&cli.BoolFlag{Name: "json", Usage: "output raw JSON"},
						},
						Action: func(ctx context.Context, c *cli.Command) error {
							cfg, err := loadConfig()
							if err != nil {
								return err
							}
							var out domain.RelationType
							if err := doRelationTypesCreate(ctx, cfg, c.String("key"), c.String("name"), c.String("description"), c.Bool("directed"), &out); err != nil {
								return err
							}
							if c.Bool("json") {
								return printJSON(out)
							}
							printRelationTypes([]domain.RelationType{out})
							return nil
						},
					},
				},
			},
			{
				Name:  "attribute-defs",
				Usage: "Manage attribute definitions",
				Commands: []*cli.Command{
					{
						Name:  "list",
						Usage: "List attribute definitions",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "scope"},
							&cli.StringFlag{Name: "q"},
							&cli.BoolFlag{Name: "json", Usage: "output raw JSON"},
						},
						Action: func(ctx context.Context, c *cli.Command) error {
							cfg, err := loadConfig()
							if err != nil {
								return err
							}
							var out []domain.AttributeDef
							if err := doAttributeDefsList(ctx, cfg, c.String("scope"), c.String("q"), &out); err != nil {
								return err
							}
							if c.Bool("json") {
								return printJSON(out)
							}
							printAttributeDefs(out)
							return nil
						},
					},
					{
						Name:  "upsert",
						Usage: "Create or update attribute definition",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "scope", Required: true},
							&cli.StringFlag{Name: "key", Required: true},
							&cli.StringFlag{Name: "value-kind", Value: "string"},
							&cli.StringFlag{Name: "description"},
							&cli.BoolFlag{Name: "json", Usage: "output raw JSON"},
						},
						Action: func(ctx context.Context, c *cli.Command) error {
							cfg, err := loadConfig()
							if err != nil {
								return err
							}
							var out domain.AttributeDef
							if err := doAttributeDefsUpsert(ctx, cfg, c.String("scope"), c.String("key"), c.String("value-kind"), c.String("description"), &out); err != nil {
								return err
							}
							if c.Bool("json") {
								return printJSON(out)
							}
							printAttributeDefs([]domain.AttributeDef{out})
							return nil
						},
					},
				},
			},
		},
	}
}

func accessCommand() *cli.Command {
	return &cli.Command{
		Name:  "access",
		Usage: "Access and users commands",
		Commands: []*cli.Command{
			{
				Name:  "users",
				Usage: "Manage users",
				Commands: []*cli.Command{
					{
						Name:  "list",
						Usage: "List users",
						Flags: []cli.Flag{&cli.StringFlag{Name: "q"}, &cli.BoolFlag{Name: "json", Usage: "output raw JSON"}},
						Action: func(ctx context.Context, c *cli.Command) error {
							cfg, err := loadConfig()
							if err != nil {
								return err
							}
							var out []domain.User
							if err := doUsersList(ctx, cfg, c.String("q"), &out); err != nil {
								return err
							}
							if c.Bool("json") {
								return printJSON(out)
							}
							printUsers(out)
							return nil
						},
					},
					{
						Name:  "create",
						Usage: "Create user",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "email", Required: true},
							&cli.StringFlag{Name: "password", Required: true},
							&cli.UintFlag{Name: "role-id"},
							&cli.BoolFlag{Name: "json", Usage: "output raw JSON"},
						},
						Action: func(ctx context.Context, c *cli.Command) error {
							cfg, err := loadConfig()
							if err != nil {
								return err
							}
							var out domain.User
							if err := doUsersCreate(ctx, cfg, c.String("email"), c.String("password"), c.Uint("role-id"), &out); err != nil {
								return err
							}
							if c.Bool("json") {
								return printJSON(out)
							}
							printUsers([]domain.User{out})
							return nil
						},
					},
				},
			},
			{
				Name:  "roles",
				Usage: "Manage roles",
				Commands: []*cli.Command{
					{
						Name:  "list",
						Usage: "List roles",
						Flags: []cli.Flag{&cli.BoolFlag{Name: "json", Usage: "output raw JSON"}},
						Action: func(ctx context.Context, c *cli.Command) error {
							cfg, err := loadConfig()
							if err != nil {
								return err
							}
							var out []domain.Role
							if err := doRolesList(ctx, cfg, &out); err != nil {
								return err
							}
							if c.Bool("json") {
								return printJSON(out)
							}
							printRoles(out)
							return nil
						},
					},
					{
						Name:  "assign",
						Usage: "Assign role to user",
						Flags: []cli.Flag{
							&cli.UintFlag{Name: "user-id", Required: true},
							&cli.UintFlag{Name: "role-id", Required: true},
							&cli.BoolFlag{Name: "json", Usage: "output raw JSON"},
						},
						Action: func(ctx context.Context, c *cli.Command) error {
							cfg, err := loadConfig()
							if err != nil {
								return err
							}
							var out map[string]any
							if err := doAssignRole(ctx, cfg, c.Uint("user-id"), c.Uint("role-id"), &out); err != nil {
								return err
							}
							if c.Bool("json") {
								return printJSON(out)
							}
							fmt.Printf("assigned role %d to user %d\n", c.Uint("role-id"), c.Uint("user-id"))
							return nil
						},
					},
				},
			},
		},
	}
}

func auditCommand() *cli.Command {
	return &cli.Command{
		Name:  "audit",
		Usage: "Audit log commands",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List audit logs",
				Flags: []cli.Flag{&cli.BoolFlag{Name: "json", Usage: "output raw JSON"}},
				Action: func(ctx context.Context, c *cli.Command) error {
					cfg, err := loadConfig()
					if err != nil {
						return err
					}
					var out []domain.AuditRecord
					if err := doAuditList(ctx, cfg, &out); err != nil {
						return err
					}
					if c.Bool("json") {
						return printJSON(out)
					}
					printAuditRecords(out)
					return nil
				},
			},
		},
	}
}

func jsonMarshal(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
