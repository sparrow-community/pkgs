package config

import (
	"encoding/json"
	"github.com/urfave/cli/v2"
	"go-micro.dev/v4/config/source"
	sc "go-micro.dev/v4/config/source/cli"
	"go-micro.dev/v4/config/source/file"
	"go-micro.dev/v4/logger"
	"go-micro.dev/v4/util/cmd"
	"os"
	"strings"
)

type Options struct {
	serverName  string
	flags       []cli.Flag
	sources     []source.Source
	defaultVals map[string]any
}

type Option func(*Options)

func WithServerName(serverName string) Option {
	return func(o *Options) {
		if len(serverName) > 0 {
			o.serverName = serverName
		}
	}
}

func WithFlags(flags ...cli.Flag) Option {
	return func(o *Options) {
		o.flags = flags
	}
}

func WithSource(sour source.Source) Option {
	return func(o *Options) {
		if sour != nil {
			o.sources = append(o.sources, sour)
		}
	}
}

func WithDefaultConfig(v any) Option {
	return func(options *Options) {
		if v != nil {
			vs, err := json.Marshal(v)
			if err != nil {
				logger.Errorf("read default config error %s", err)
				return
			}
			if err := json.Unmarshal(vs, &options.defaultVals); err != nil {
				logger.Errorf("read default config error %s", err)
			}
		}
	}
}

// LocalFileSource read local file source
func LocalFileSource(path string) source.Source {
	exists := func(path string) (bool, error) {
		_, err := os.Stat(path)
		if err == nil {
			return true, nil
		}
		if os.IsNotExist(err) {
			return false, nil
		}
		return true, err
	}

	b, err := exists(path)
	if err != nil {
		logger.Error(err)
		return nil
	}
	if b {
		return file.NewSource(file.WithPath(path))
	}
	return nil
}

// cliSource read startup variables & environment variables
func cliSource(serverName string, flags ...cli.Flag) source.Source {
	var cliSource source.Source
	app := cmd.DefaultCmd.App()
	for idx, f := range app.Flags {
		if strings.Contains(strings.Join(f.Names(), ","), "server_name") {
			app.Flags[idx] = &cli.StringFlag{
				Name:    "server_name",
				EnvVars: []string{"MICRO_SERVER_NAME"},
				Value:   serverName,
				Usage:   "Name of the server. go.micro.srv.example",
			}
		}
	}

	app.Flags = append(app.Flags, flags...)

	app.Action = func(ctx *cli.Context) error {
		cliSource = sc.NewSource(sc.Context(ctx))
		return nil
	}
	_ = app.Run(os.Args)
	return cliSource
}
