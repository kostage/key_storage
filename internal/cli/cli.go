package cli

import (
	"github.com/alecthomas/kong"
	"github.com/rs/zerolog"
)

type CLI struct {
	Password PasswordCmd `cmd:"" help:"Remove files."`
	Create   CreateCmd   `cmd:"" help:"Remove files."`
	File     string      `help:"Remove files." short:"f" default:"passwords"`
	Verbose  bool        `help:"Remove files." short:"v" default:"false"`
}

func (cli *CLI) AfterApply(
	kongCtx *kong.Context,
) error {
	if cli.Verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	}
	kongCtx.BindTo(cli.File, (*string)(nil))
	return nil
}

func NewCLI() *CLI {
	return &CLI{}
}
