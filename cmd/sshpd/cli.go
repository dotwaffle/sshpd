package main

import (
	"errors"

	"github.com/dotwaffle/sshpd/internal/daemon"
)

type userName struct {
	Name string `arg:"" help:"User name."`
}

type adminCommand struct {
	Socket string `required:"" help:"Private administration socket path." placeholder:"PATH"`
	User   struct {
		List    struct{} `cmd:"" help:"List users and enrolled passkeys."`
		Add     userName `cmd:"" help:"Create a user and enrollment invitation."`
		Invite  userName `cmd:"" help:"Invite a user to add a passkey."`
		Recover userName `cmd:"" help:"Revoke credentials and issue a recovery invitation."`
		Disable userName `cmd:"" help:"Disable a user and revoke access."`
		Delete  userName `cmd:"" help:"Delete a user and revoke access."`
	} `cmd:"" help:"Manage users."`
	Key struct {
		Remove struct {
			Name  string `arg:"" help:"User name."`
			KeyID string `arg:"" help:"Passkey ID."`
		} `cmd:"" help:"Remove a passkey and revoke its logins."`
	} `cmd:"" help:"Manage passkeys."`
	Backup struct {
		Name string `arg:"" help:"Backup name."`
	} `cmd:"" help:"Create a sanitized database backup."`
}

func (a *adminCommand) request(selected string) (daemon.AdminRequest, error) {
	var input daemon.AdminRequest
	switch selected {
	case "admin user list":
		input.Action = "users"
	case "admin user add <name>":
		input.Action, input.Name = "user-add", a.User.Add.Name
	case "admin user invite <name>":
		input.Action, input.Name = "user-invite", a.User.Invite.Name
	case "admin user recover <name>":
		input.Action, input.Name = "user-recover", a.User.Recover.Name
	case "admin user disable <name>":
		input.Action, input.Name = "user-disable", a.User.Disable.Name
	case "admin user delete <name>":
		input.Action, input.Name = "user-delete", a.User.Delete.Name
	case "admin key remove <name> <key-id>":
		input.Action, input.Name, input.KeyID = "key-remove", a.Key.Remove.Name, a.Key.Remove.KeyID
	case "admin backup <name>":
		input.Action, input.Name = "backup", a.Backup.Name
	default:
		return input, errors.New("unknown administration command")
	}
	return input, nil
}

type serverCLI struct {
	Serve struct {
		Config string `default:"sshpd.json" help:"Strict JSON configuration file." placeholder:"FILE"`
	} `cmd:"" help:"Serve SSH relay traffic and private administration."`
	Admin adminCommand `cmd:"" help:"Manage users, passkeys, and backups through the private socket."`
}
