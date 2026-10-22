package command

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

type testCLI struct {
	Serve struct {
		Config string `default:"default.json"`
	} `cmd:""`
}

func TestParseDoubleDashFlags(t *testing.T) {
	for _, tc := range []struct {
		args []string
		ok   bool
	}{
		{[]string{"serve", "--config", "selected.json"}, true},
		{[]string{"serve", "--config=selected.json"}, true},
		{[]string{"serve", "-config", "selected.json"}, false},
		{[]string{"serve", "-config=selected.json"}, false},
	} {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			var cli testCLI
			selected, err := Parse(&cli, "test", tc.args, io.Discard, io.Discard)
			if (err == nil) != tc.ok {
				t.Fatal("unexpected flag acceptance", err)
			}
			if tc.ok && (selected != "serve" || cli.Serve.Config != "selected.json") {
				t.Fatal("incorrect selection")
			}
		})
	}
}

func TestParseHelpReturnsWithoutSelectingCommand(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"--help"}, {"-h"}, {"serve", "--help"}, {"help", "serve"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var cli testCLI
			var out bytes.Buffer
			selected, err := Parse(&cli, "test", args, &out, io.Discard)
			if err != nil || selected != "" || !strings.Contains(out.String(), "Usage: test") {
				t.Fatal("help failed or selected an operation", selected, err)
			}
		})
	}
}
