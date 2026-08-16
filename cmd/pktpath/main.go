package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ppp16bit/pktpath/internal/cli"
	"github.com/ppp16bit/pktpath/internal/enrich"
	"github.com/ppp16bit/pktpath/internal/trace"
	"github.com/ppp16bit/pktpath/internal/ui"
)

const version = "0.1.0"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "pktpath: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	options, err := cli.Parse(args)
	if err != nil {
		fmt.Fprint(stderr, cli.Usage)
		return err
	}
	if options.Help {
		_, err := fmt.Fprint(stdout, cli.Usage)
		return err
	}
	if options.Version {
		_, err := fmt.Fprintf(stdout, "pktpath %s\n", version)
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	totalStarted := time.Now()
	debug := (*ui.DebugRenderer)(nil)
	if options.Debug {
		debug = ui.NewDebugRenderer(stderr)
	}
	progress := ui.NewProgress(stderr, options.Destination, animationEnabled(
		options, isTerminal(stdout), isTerminal(stderr),
	))
	defer progress.Stop()

	resolveStarted := time.Now()
	target, err := trace.ResolveTarget(ctx, options.Destination)
	if err != nil {
		if debug != nil {
			debug.ResolveFailed(options.Destination, err, time.Since(resolveStarted))
		}
		return err
	}
	progress.Resolved()
	if debug != nil {
		debug.Resolve(options.Destination, target, time.Since(resolveStarted))
	}

	traceStarted := time.Now()
	traceObserver := func(event trace.Event) {
		progress.Trace(event)
		if debug != nil {
			debug.Trace(event)
		}
	}
	result, err := (trace.Tracer{Config: options.Config, Observe: traceObserver}).Trace(ctx, options.Destination, target)
	if err != nil {
		if debug != nil {
			debug.TraceFailed(err, time.Since(traceStarted))
		}
		if errors.Is(err, context.Canceled) {
			return errors.New("trace canceled")
		}
		return err
	}
	if debug != nil {
		debug.TraceCompleted(result, time.Since(traceStarted))
	}

	var geoProvider enrich.GeoProvider
	if !options.NoGeo {
		geoProvider = enrich.NewIPWhoISProvider(nil)
	}
	hops := (enrich.Enricher{
		ReverseDNS: !options.NoDNS,
		Geo:        geoProvider,
		Observe: func(event enrich.Event) {
			progress.Enrich(event)
			if debug != nil {
				debug.Enrich(event)
			}
		},
	}).Enrich(ctx, result.Hops)
	progress.Stop()

	if debug == nil {
		return render(stdout, options, result, hops, colorEnabled(stdout))
	}
	var output bytes.Buffer
	renderStarted := time.Now()
	if err := render(&output, options, result, hops, colorEnabled(stdout)); err != nil {
		return err
	}
	debug.RenderingCompleted(time.Since(renderStarted))
	debug.TotalCompleted(time.Since(totalStarted))
	if options.JSON {
		_, _ = fmt.Fprintln(stderr)
	}
	_, err = io.Copy(stdout, &output)
	return err
}

func render(writer io.Writer, options cli.Options, result trace.Result, hops []enrich.HopInfo, color bool) error {
	if options.JSON {
		return ui.WriteJSON(writer, result, hops)
	}
	return ui.WriteHuman(writer, result, hops, ui.HumanOptions{
		Color: color, ShowPrivate: options.ShowPrivate,
	})
}

func animationEnabled(options cli.Options, stdoutTTY, stderrTTY bool) bool {
	return stdoutTTY && stderrTTY && !options.JSON && !options.Debug
}

func isTerminal(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func colorEnabled(writer io.Writer) bool {
	return isTerminal(writer) && os.Getenv("NO_COLOR") == ""
}
