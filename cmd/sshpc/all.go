package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/dotwaffle/sshpd/internal/agent"
)

func allServers(ctx context.Context, command, socket string, out io.Writer) error {
	var status agent.AllStatus
	var results []agent.LogoutResult
	var response any = &status
	if command == "logout" {
		response = &results
	}
	code, err := agent.Call(ctx, socket, "/"+command+"/all", agent.Request{}, response)
	if code == http.StatusNotFound {
		return errors.New("private agent does not support all-server commands; restart it with the updated sshpc")
	}
	if err != nil {
		return err
	}
	if err := json.NewEncoder(out).Encode(response); err != nil {
		return err
	}
	var failures []error
	for _, result := range results {
		if !result.LoggedOut {
			failures = append(failures, fmt.Errorf("logout failed for %s; credentials retained for retry", result.Server))
		}
	}
	return errors.Join(failures...)
}
