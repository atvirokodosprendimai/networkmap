package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

type rpcClient struct {
	socket string
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
	ID      int    `json:"id"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcRespError   `json:"error"`
	ID      any             `json:"id"`
}

type rpcRespError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func newRPCClient(socket string) *rpcClient {
	return &rpcClient{socket: socket}
}

func (c *rpcClient) call(ctx context.Context, method string, params any, out any) error {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", c.socket)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	req := rpcRequest{JSONRPC: "2.0", Method: method, Params: params, ID: 1}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}

	var resp rpcResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return err
	}
	if resp.Error != nil {
		return fmt.Errorf("rpc error (%d): %s", resp.Error.Code, resp.Error.Message)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(resp.Result, out)
}
