// Package cli parses pktpath's deliberately small command-line interface.
package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ppp16bit/pktpath/internal/trace"
)

type Options struct {
	Destination string
	Config      trace.Config
	NoGeo       bool
	NoDNS       bool
	ShowPrivate bool
	Debug       bool
	JSON        bool
	Help        bool
	Version     bool
}

func Parse(args []string) (Options, error) {
	options := Options{Config: trace.DefaultConfig()}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		name, inlineValue, hasInlineValue := strings.Cut(argument, "=")
		switch name {
		case "-h", "--help":
			if hasInlineValue {
				return options, fmt.Errorf("%s does not take a value", name)
			}
			options.Help = true
		case "-v", "--version":
			if hasInlineValue {
				return options, fmt.Errorf("%s does not take a value", name)
			}
			options.Version = true
		case "--no-geo":
			if hasInlineValue {
				return options, fmt.Errorf("%s does not take a value", name)
			}
			options.NoGeo = true
		case "--no-dns":
			if hasInlineValue {
				return options, fmt.Errorf("%s does not take a value", name)
			}
			options.NoDNS = true
		case "--show-private":
			if hasInlineValue {
				return options, fmt.Errorf("%s does not take a value", name)
			}
			options.ShowPrivate = true
		case "--debug":
			if hasInlineValue {
				return options, fmt.Errorf("%s does not take a value", name)
			}
			options.Debug = true
		case "--json":
			if hasInlineValue {
				return options, fmt.Errorf("%s does not take a value", name)
			}
			options.JSON = true
		case "-s", "--size", "-m", "--max-hops", "-t", "--timeout":
			value := inlineValue
			if !hasInlineValue {
				index++
				if index >= len(args) {
					return options, fmt.Errorf("%s requires a value", name)
				}
				value = args[index]
			}
			if err := setValue(&options, name, value); err != nil {
				return options, err
			}
		default:
			if strings.HasPrefix(argument, "-") {
				return options, fmt.Errorf("unknown option %q", argument)
			}
			if options.Destination != "" {
				return options, errors.New("exactly one destination is required")
			}
			options.Destination = argument
		}
	}

	if options.Help || options.Version {
		return options, nil
	}
	if options.Destination == "" {
		return options, errors.New("destination is required")
	}
	if err := options.Config.Validate(); err != nil {
		return options, err
	}
	return options, nil
}

func setValue(options *Options, name, value string) error {
	switch name {
	case "-s", "--size":
		size, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid packet size %q", value)
		}
		options.Config.PacketSize = size
	case "-m", "--max-hops":
		maxHops, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid maximum hops %q", value)
		}
		options.Config.MaxHops = maxHops
	case "-t", "--timeout":
		timeout, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid timeout %q: use a duration such as 500ms or 2s", value)
		}
		options.Config.Timeout = timeout
	}
	return nil
}

const Usage = `Usage: pktpath [options] <destination>

Trace the forward path observed with IPv4 ICMP diagnostic probes.

Options:
  -s, --size <bytes>       intended total IPv4 packet size (default 64; min 28)
  -m, --max-hops <n>       maximum number of hops (default 30)
  -t, --timeout <duration> timeout per probe (default 2s)
      --no-geo             disable GeoIP/ASN enrichment
      --no-dns             disable reverse DNS
      --show-private       reveal private/shared addresses in human output
      --debug              print enrichment diagnostics to stderr
      --json               emit unstyled structured JSON
  -h, --help               show help
  -v, --version            show version
`
