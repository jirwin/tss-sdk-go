package main

import (
	"context"
	"os"

	"github.com/jirwin/ctxzap"
	"go.uber.org/zap"

	"github.com/jirwin/tss-sdk-go/client"
)

func initLogging(ctx context.Context) context.Context {
	_ = os.Stdout.Sync()

	l := zap.Must(zap.NewDevelopment())
	zap.ReplaceGlobals(l)

	return ctxzap.ToContext(ctx, l)
}

func main() {
	ctx := initLogging(context.Background())
	l := ctxzap.Extract(ctx)

	tss, err := client.New(os.Getenv("TSS_URL"), nil, client.WithPasswordAuth(os.Getenv("TSS_USERNAME"), os.Getenv("TSS_PASSWORD")))
	if err != nil {
		l.Error("Error initializing the client", zap.Error(err))
		os.Exit(1)
	}

	s, err := tss.Secret(ctx, 1)
	if err != nil {
		l.Error("Error calling tss.Secret", zap.Error(err))
		os.Exit(1)
	}

	if pw, ok := s.Field(ctx, "password"); ok {
		l.Info("the password was retrieved successfully", zap.String("password", pw))
	}

	s1, err := tss.Secret(ctx, 1)
	if err != nil {
		l.Error("Error calling tss.Secret", zap.Error(err))
		os.Exit(1)
	}

	if pw, ok := s1.Field(ctx, "password"); ok {
		l.Info("the password was retrieved successfully", zap.String("password", pw))
	}
}
