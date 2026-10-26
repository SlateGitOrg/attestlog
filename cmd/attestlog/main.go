// Command attestlog creates and verifies SLSA provenance attestations and
// runs an offline transparency log for them. See "attestlog help".
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/SlateGitOrg/attestlog/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
