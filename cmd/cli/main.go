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
	server := pflag.String("server", "127.0.0.1:1812", "RADIUS server address")
	secret := pflag.String("secret", "", "Shared secret with the RADIUS server (required)")
	username := pflag.String("username", "", "Username for authentication (required)")
	password := pflag.String("password", "", "Password for authentication (required)")
	chap := pflag.Bool("chap", false, "Use CHAP authentication instead of PAP")
	mschap := pflag.Bool("mschap", false, "Use MS-CHAP authentication instead of PAP")

	// Check for -h/--help before pflag.Parse
	for _, arg := range os.Args {
		if arg == "-h" || arg == "--help" {
			printUsage()
			os.Exit(0)
		}
	}

	pflag.Parse()

	config := RadiusClientConfig{
		Username: *username,
		Password: *password,
		Secret:   *secret,
		Server:   *server,
	}

	if err := validateConfig(config); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		printUsage()
		os.Exit(1)
	}

	client := NewRadiusClient(config.Server, config.Secret)

	fmt.Printf("Sending Access-Request to %s...\n", config.Server)
	fmt.Printf("Username: %s\n", config.Username)

	var response []byte
	var err error

	if *chap {
		fmt.Println("Using CHAP authentication")
		response, err = client.SendCHAPAccessRequest(config.Username, config.Password)
	} else if *mschap {
		fmt.Println("Using MS-CHAP authentication")
		response, err = client.SendMSCHAPAccessRequest(config.Username, config.Password)
	} else {
		response, err = client.SendAccessRequest(config.Username, config.Password)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	DisplayResponse(response)
}

// validateConfig checks that all required flags are present.
func validateConfig(config RadiusClientConfig) error {
	if config.Secret == "" {
		return fmt.Errorf("-secret flag is required")
	}
	if config.Username == "" {
		return fmt.Errorf("-username flag is required")
	}
	if config.Password == "" {
		return fmt.Errorf("-password flag is required")
	}
	return nil
}

// printUsage prints custom usage in the desired order.
func printUsage() {
	fmt.Println("Usage: radius-cli [options]")
	fmt.Println("Options:")
	fmt.Println("  --server    RADIUS server address (default 127.0.0.1:1812)")
	fmt.Println("  --secret    Shared secret with the RADIUS server (required)")
	fmt.Println("  --username  Username for authentication (required)")
	fmt.Println("  --password  Password for authentication (required)")
	fmt.Println("  --chap      Use CHAP authentication (required with enterprise WiFi)")
	fmt.Println("  --mschap    Use MS-CHAP authentication (required with Windows AD)")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  radius-cli --server 127.0.0.1:1812 --secret testing123 --username alice --password test")
	fmt.Println("  radius-cli --secret testing123 --username alice --password test --server 192.168.1.100:1812")
	fmt.Println("  radius-cli --secret testing123 --username alice --password test --chap")
	fmt.Println("  radius-cli --secret testing123 --username alice --password test --mschap")
}
