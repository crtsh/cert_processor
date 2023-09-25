package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/crtsh/cert_processor/certwatch"
	"github.com/crtsh/cert_processor/logger"
	"github.com/crtsh/cert_processor/server"
)

func main() {
	// The certwatch database connections, which were opened automatically by the init() function, need to be closed on exit.
	defer certwatch.Close()

	// Configure graceful shutdown capabilities.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer certwatch.ShutdownWG.Wait()

	// Start the N goroutines.
	certwatch.ShutdownWG.Add(1)
	go certwatch.CertProcessor(ctx)

	// Start the Monitoring HTTP server.
	server.Run()
	defer server.Shutdown()

	// Wait to be interrupted.
	<-ctx.Done()

	// Ensure all log messages are flushed before we exit.
	logger.Logger.Sync()
}
