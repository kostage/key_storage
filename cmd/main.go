package main

import (
	"context"

	"github.com/alecthomas/kong"
	"github.com/kostage/key_storage/internal/cli"
)

func main() {
	cli := cli.NewCLI()
	ctx := context.Background()
	handler := kong.Parse(cli, kong.BindTo(ctx, (*context.Context)(nil)))
	err := handler.Run()
	handler.FatalIfErrorf(err)
}
