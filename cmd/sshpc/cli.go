package main

import "time"

type ServerFlags struct {
	Server *string `help:"Public HTTPS relay origin. Omit for all servers in status/logout." placeholder:"HTTPS_ORIGIN"`
}

type ConfiguredFlags struct {
	ServerFlags
	Config string `help:"Client configuration file; overrides user and system files." placeholder:"PATH"`
}

type proxyCommand struct {
	ConfiguredFlags
	Host         string        `required:"" help:"SSH destination host."`
	Port         uint          `default:"22" help:"SSH destination port."`
	ResumeWindow time.Duration `default:"30m" help:"Maximum retry time after transport loss."`
}

type clientCLI struct {
	AgentSocket string          `help:"Private native credential-agent socket." placeholder:"PATH"`
	Login       ConfiguredFlags `cmd:"" help:"Approve a native login using a passkey."`
	Status      ServerFlags     `cmd:"" help:"Show native login status for all servers, or --server."`
	Logout      ServerFlags     `cmd:"" help:"Revoke native logins for all servers, or --server."`
	Proxy       proxyCommand    `cmd:"" help:"Connect OpenSSH to an allowed relay destination."`
	Agent       struct{}        `cmd:"" help:"Run the private credential agent in the foreground."`
}
