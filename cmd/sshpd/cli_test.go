package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/dotwaffle/sshpd/internal/command"
)

func TestAdminArgumentShapes(t *testing.T) {
	for _, tc := range []struct {
		args              []string
		action, name, key string
	}{
		{[]string{"user", "list"}, "users", "", ""},
		{[]string{"user", "add", "alice"}, "user-add", "alice", ""},
		{[]string{"user", "invite", "alice"}, "user-invite", "alice", ""},
		{[]string{"user", "recover", "alice"}, "user-recover", "alice", ""},
		{[]string{"user", "disable", "alice"}, "user-disable", "alice", ""},
		{[]string{"user", "delete", "alice"}, "user-delete", "alice", ""},
		{[]string{"key", "remove", "alice", "key"}, "key-remove", "alice", "key"},
		{[]string{"backup", "snapshot.db"}, "backup", "snapshot.db", ""},
		{[]string{"user", "list", "extra"}, "", "", ""},
		{[]string{"user", "add"}, "", "", ""},
		{[]string{"key", "remove", "alice"}, "", "", ""},
		{[]string{"backup", "snapshot.db", "extra"}, "", "", ""},
		{[]string{"users"}, "", "", ""},
		{[]string{"user-add", "alice"}, "", "", ""},
	} {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			var cli serverCLI
			args := append([]string{"admin", "--socket", "/unused"}, tc.args...)
			selected, err := command.Parse(&cli, "sshpd", args, io.Discard, io.Discard)
			if (err == nil) != (tc.action != "") {
				t.Fatal("unexpected argument acceptance", err)
			}
			if err != nil {
				return
			}
			input, err := cli.Admin.request(selected)
			if err != nil || input.Action != tc.action || input.Name != tc.name || input.KeyID != tc.key {
				t.Fatal("incorrect admin request", input, err)
			}
		})
	}
}

func TestServerHelpDoesNotStartService(t *testing.T) {
	for _, args := range [][]string{{"serve", "--help"}, {"admin", "--help"}, {"help", "admin"}} {
		var out bytes.Buffer
		if err := run(t.Context(), args, &out, io.Discard); err != nil || !strings.Contains(out.String(), "Usage: sshpd") {
			t.Fatal("server help failed", err)
		}
	}
}
