package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type cliConfig struct {
	Transport string `json:"transport"`
	Server    string `json:"server"`
	Socket    string `json:"socket"`
	Token     string `json:"token"`
}

type apiClient struct {
	httpClient *http.Client
	server     string
	token      string
}

func newAPIClient(server, token string) *apiClient {
	return &apiClient{
		httpClient: &http.Client{Timeout: 20 * time.Second},
		server:     strings.TrimRight(server, "/"),
		token:      token,
	}
}

func (c *apiClient) request(ctx context.Context, method, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		buf := &bytes.Buffer{}
		if err := json.NewEncoder(buf).Encode(in); err != nil {
			return err
		}
		body = buf
	}

	req, err := http.NewRequestWithContext(ctx, method, c.server+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		payload, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("api error (%d): %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".networkmap", "config.json"), nil
}

func loadConfig() (cliConfig, error) {
	path, err := configPath()
	if err != nil {
		return cliConfig{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cliConfig{Transport: "uds", Server: "http://127.0.0.1:8080", Socket: "/tmp/networkmap.sock"}, nil
		}
		return cliConfig{}, err
	}
	var cfg cliConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cliConfig{}, err
	}
	if cfg.Transport == "" {
		cfg.Transport = "uds"
	}
	if cfg.Server == "" {
		cfg.Server = "http://127.0.0.1:8080"
	}
	if cfg.Socket == "" {
		cfg.Socket = "/tmp/networkmap.sock"
	}
	return cfg, nil
}

func saveConfig(cfg cliConfig) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return nil
}
