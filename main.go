package main

import (
	"context"
	"os"

	"github.com/jirwin/ctxzap"
	"go.uber.org/zap"

	"github.com/DelineaXPM/tss-sdk-go/v2/server"
)

func initLogging(ctx context.Context) context.Context {
	_ = os.Stdout.Sync()

	l := zap.Must(zap.NewProduction())
	zap.ReplaceGlobals(l)

	return ctxzap.ToContext(ctx, l)
}

func main() {
	ctx := initLogging(context.Background())
	l := ctxzap.Extract(ctx)

	tss, err := server.New(server.Configuration{
		Credentials: server.UserCredential{
			Username: os.Getenv("TSS_USERNAME"),
			Password: os.Getenv("TSS_PASSWORD"),
		},
		Tenant: os.Getenv("TSS_TENANT"),
	})

	if err != nil {
		l.Error("Error initializing the server configuration", zap.Error(err))
		os.Exit(1)
	}

	s, err := tss.Secret(ctx, 1)

	if err != nil {
		l.Error("Error calling server.Secret", zap.Error(err))
		os.Exit(1)
	}

	if pw, ok := s.Field(ctx, "password"); ok {
		l.Info("the password was retrieved successfully", zap.String("password", pw))
	}
}
