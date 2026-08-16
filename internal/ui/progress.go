package ui

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/ppp16bit/pktpath/internal/enrich"
	"github.com/ppp16bit/pktpath/internal/trace"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type Progress struct {
	spinner     *spinner
	destination string
	hops        int
}

func NewProgress(writer io.Writer, destination string, enabled bool) *Progress {
	return newProgress(writer, destination, enabled, 80*time.Millisecond)
}

func newProgress(writer io.Writer, destination string, enabled bool, interval time.Duration) *Progress {
	progress := &Progress{destination: destination}
	if enabled {
		progress.spinner = newSpinner(writer, interval)
		progress.spinner.start(fmt.Sprintf("Resolving target %s...", destination))
	}
	return progress
}

func (progress *Progress) Resolved() {
	if progress.Enabled() {
		progress.spinner.update(fmt.Sprintf("Tracing route to %s...", progress.destination))
	}
}

func (progress *Progress) Enabled() bool {
	return progress != nil && progress.spinner != nil
}

func (progress *Progress) Trace(event trace.Event) {
	if !progress.Enabled() {
		return
	}
	switch event.Kind {
	case trace.EventProbeStarted:
		if progress.hops == 0 {
			progress.spinner.update(fmt.Sprintf("Tracing route to %s... hop %d · waiting for response", progress.destination, event.Hop.Number))
		} else {
			progress.spinner.update(fmt.Sprintf("Tracing route to %s... %d hops · hop %d · waiting for response", progress.destination, progress.hops, event.Hop.Number))
		}
	case trace.EventHopCompleted:
		progress.hops = event.Hop.Number
		progress.spinner.update(fmt.Sprintf("Tracing route to %s... %d hops", progress.destination, event.Hop.Number))
	}
}

// Enrich consumes terminal-independent enrichment events.
func (progress *Progress) Enrich(event enrich.Event) {
	if !progress.Enabled() {
		return
	}
	var label string
	switch event.Stage {
	case enrich.StageReverseDNS:
		label = "Resolving hostnames"
	case enrich.StageGeoASN:
		label = "Resolving network information"
	default:
		return
	}
	switch event.Kind {
	case enrich.EventStageStarted:
		progress.spinner.update(fmt.Sprintf("%s... 0/%d", label, event.Total))
	case enrich.EventStageProgress:
		progress.spinner.update(fmt.Sprintf("%s... %d/%d", label, event.Current, event.Total))
	}
}

func (progress *Progress) Stop() {
	if progress != nil && progress.spinner != nil {
		progress.spinner.stop()
	}
}

type spinner struct {
	writer   io.Writer
	interval time.Duration

	mu      sync.Mutex
	message string
	frame   int
	done    chan struct{}
	stopped chan struct{}
	once    sync.Once
}

func newSpinner(writer io.Writer, interval time.Duration) *spinner {
	return &spinner{writer: writer, interval: interval, done: make(chan struct{}), stopped: make(chan struct{})}
}

func (spinner *spinner) start(message string) {
	spinner.update(message)
	spinner.render()
	go spinner.animate()
}

func (spinner *spinner) update(message string) {
	spinner.mu.Lock()
	spinner.message = message
	spinner.mu.Unlock()
}

func (spinner *spinner) animate() {
	defer close(spinner.stopped)
	ticker := time.NewTicker(spinner.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			spinner.render()
		case <-spinner.done:
			return
		}
	}
}

func (spinner *spinner) render() {
	spinner.mu.Lock()
	frame := spinnerFrames[spinner.frame%len(spinnerFrames)]
	spinner.frame++
	message := spinner.message
	spinner.mu.Unlock()
	_, _ = fmt.Fprintf(spinner.writer, "\r\x1b[2K%s %s", frame, message)
}

func (spinner *spinner) stop() {
	spinner.once.Do(func() {
		close(spinner.done)
		<-spinner.stopped
		_, _ = fmt.Fprint(spinner.writer, "\r\x1b[2K")
	})
}
