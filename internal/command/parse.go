// Package command supplies common command-line parsing and help behavior.
package command

import (
	"errors"
	"io"

	"github.com/alecthomas/kong"
)

var errHelp = errors.New("help displayed")

// Parse returns the selected command, or an empty string after displaying help.
func Parse(model any, name string, args []string, out, errOut io.Writer) (string, error) {
	parser, err := kong.New(model, kong.Name(name), kong.Writers(out, errOut), kong.Help(func(options kong.HelpOptions, ctx *kong.Context) error {
		if err := kong.DefaultHelpPrinter(options, ctx); err != nil {
			return err
		}
		return errHelp
	}))
	if err != nil {
		return "", err
	}
	args = append([]string(nil), args...)
	if len(args) == 0 {
		args = []string{"--help"}
	} else if args[0] == "help" {
		args = append(args[1:], "--help")
	}
	ctx, err := parser.Parse(args)
	if errors.Is(err, errHelp) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return ctx.Command(), nil
}
