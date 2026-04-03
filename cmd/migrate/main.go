// Command migrate runs database migrations for the auth service.
// Usage: go run cmd/migrate/main.go [up|down|version]
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: migrate <up|down|version>\n")
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "up", "down", "version":
		fmt.Printf("migrate %s: not yet implemented\n", cmd)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		os.Exit(1)
	}
}
