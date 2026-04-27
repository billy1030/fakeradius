// Package cli implements the Fake RADIUS query tool.
// It sends Access-Request packets to a RADIUS server and displays the response.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
)

// RadiusClientConfig holds the CLI configuration.
type RadiusClientConfig struct {
	Username string
	Password string
	Secret   string
	Server   string
}

func main() {
	pflag.CommandLine = pflag.NewFlagSet("radius-cli", pflag.ExitOnError)

	username := pflag.String("username", "", "Username for authentication (required)")
	server := pflag.String("server", "127.0.0.1:1812", "RADIUS server address")
	secret := pflag.String("secret", "", "Shared secret with the RADIUS server (required)")
	password := pflag.String("password", "", "Password for authentication (required)")

	pflag.Parse()

	config := RadiusClientConfig{
		Username: *username,
		Password: *password,
		Secret:   *secret,
		Server:   *server,
	}

	if err := validateConfig(config); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		pflag.Usage()
		os.Exit(1)
	}

	client := NewRadiusClient(config.Server, config.Secret)

	fmt.Printf("Sending Access-Request to %s...\n", config.Server)
	fmt.Printf("Username: %s\n", config.Username)

	response, err := client.SendAccessRequest(config.Username, config.Password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	DisplayResponse(response)
}

// validateConfig checks that all required flags are present.
func validateConfig(config RadiusClientConfig) error {
	if config.Username == "" {
		return fmt.Errorf("-username flag is required")
	}
	if config.Password == "" {
		return fmt.Errorf("-password flag is required")
	}
	if config.Secret == "" {
		return fmt.Errorf("-secret flag is required")
	}
	return nil
}