// Command planboard-importer sends a local planning root to the Planboard
// service as the first commit of a new board, following the import protocol.
//
//	PLANBOARD_IMPORT_TOKEN=<token> planboard-importer <url> [dir] [--check]
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/choria-io/fisk"
)

// version is the version reported by --version, set at build time.
var version = "development"

// tokenVariable holds the import's token. It is read from the environment
// alone, so the token is never on a command line.
const tokenVariable = "PLANBOARD_IMPORT_TOKEN"

type command struct {
	url   string
	dir   string
	check bool
	ok    bool
}

func main() {
	// An argument starting with @ is taken as written, not as a file of
	// arguments.
	fisk.EnableFileExpansion = false

	cmd := &command{}

	app := fisk.New("planboard-importer", "Imports a planning root into a new Planboard board, with the token in "+tokenVariable)
	app.Version(version)
	app.HelpFlag.Short('h')
	app.Arg("url", "The import URL the accounts pages showed").Required().StringVar(&cmd.url)
	app.Arg("dir", "The planning root to import").Default(".").StringVar(&cmd.dir)
	app.Flag("check", "Runs every check without landing").UnNegatableBoolVar(&cmd.check)
	app.Action(cmd.action)

	app.MustParseWithUsage(os.Args[1:])

	if !cmd.ok {
		os.Exit(1)
	}
}

func (c *command) action(_ *fisk.ParseContext) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	c.ok = run(ctx, options{
		url:      c.url,
		dir:      c.dir,
		token:    os.Getenv(tokenVariable),
		check:    c.check,
		out:      os.Stdout,
		terminal: terminal(os.Stdout),
	})

	return nil
}

// terminal tells whether f is a terminal, where progress bars are shown.
func terminal(f *os.File) bool {
	info, err := f.Stat()

	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
