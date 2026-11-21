package main

import (
	"io"
	"time"

	"github.com/jedib0t/go-pretty/v6/progress"
)

// meter shows a progress bar of bytes while files are hashed or sent. A nil
// meter, as startMeter gives when the output is not a terminal, shows nothing.
// Nothing else is written while one runs, so stop it before printing.
type meter struct {
	pw      progress.Writer
	tracker *progress.Tracker
	done    chan struct{}
}

// startMeter starts a bar of total bytes, labeled with message unless it is
// empty, when the bar shows alone.
func (im *importer) startMeter(message string, total int64) *meter {
	if !im.terminal {
		return nil
	}

	style := progress.StyleDefault
	if message == "" {
		style.Options.Separator = ""
	}

	pw := progress.NewWriter()
	pw.SetOutputWriter(im.out)
	pw.SetStyle(style)
	pw.SetUpdateFrequency(100 * time.Millisecond)

	m := &meter{
		pw:      pw,
		tracker: &progress.Tracker{Message: message, Total: total, Units: progress.UnitsBytes},
		done:    make(chan struct{}),
	}
	pw.AppendTracker(m.tracker)

	go func() {
		pw.Render()
		close(m.done)
	}()

	return m
}

// Write counts bytes, so a meter can sit beside a hash in io.MultiWriter.
func (m *meter) Write(p []byte) (int, error) {
	if m != nil {
		m.tracker.Increment(int64(len(p)))
	}

	return len(p), nil
}

// stop renders the last state and returns once the bar is written.
func (m *meter) stop(ok bool) {
	if m == nil {
		return
	}

	if ok {
		m.tracker.MarkAsDone()
	} else {
		m.tracker.MarkAsErrored()
	}

	// A Stop before Render has begun is lost, so it is repeated until Render
	// returns.
	for {
		m.pw.Stop()

		select {
		case <-m.done:
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// countingReader feeds a meter as a body is read.
type countingReader struct {
	r io.Reader
	m *meter
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.m.Write(p[:n])

	return n, err
}
