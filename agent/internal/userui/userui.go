// Package userui talks to the person sitting at the device: notifications,
// yes/no questions (session consent, reboot deferral) and the visible
// "remote session active" indicator.
//
// The agent runs as a service without a desktop, so every implementation
// shows its UI inside the logged-in console user's session. When nobody is
// logged in there is nobody to ask: Confirm reports asked=false and callers
// decide what that means (see docs/PROTOCOL.md section 6.5).
package userui

import (
	"context"
	"sync"
	"time"
)

// Question is a yes/no prompt.
type Question struct {
	Title   string
	Message string
	// YesLabel and NoLabel are button captions where the OS allows custom ones.
	YesLabel string
	NoLabel  string
	// Timeout after which DefaultYes is returned. Zero means 60 seconds.
	Timeout    time.Duration
	DefaultYes bool
}

// UI is implemented per operating system.
type UI interface {
	// Notify shows a short notification to the logged-in user. It is a no-op
	// (nil error) when nobody is logged in.
	Notify(ctx context.Context, title, message string) error

	// Confirm asks the logged-in user. asked is false when there was nobody to
	// ask or no way to show a prompt; yes then carries no meaning.
	Confirm(ctx context.Context, q Question) (yes bool, asked bool, err error)

	// ShowIndicator shows a persistent, visible indicator (for example
	// "Remote session active: Jane Doe (Example IT)") until stop is called.
	// ended is closed if the user chooses "End session" on the indicator.
	// shown is false when nobody is logged in.
	ShowIndicator(ctx context.Context, title, message string) (stop func(), ended <-chan struct{}, shown bool, err error)
}

// Fake is a scriptable UI for tests.
type Fake struct {
	mu sync.Mutex
	// Answer is returned by Confirm; Asked controls the asked result.
	Answer bool
	Asked  bool
	// Shown controls the shown result of ShowIndicator.
	Shown bool
	// TimesOut makes Confirm behave like an unanswered prompt: it blocks for
	// the question's timeout (or until ctx ends) and returns DefaultYes.
	TimesOut bool
	// ConfirmErr, NotifyErr and IndicatorErr are returned by the respective
	// calls when set (Confirm then reports asked=false, ShowIndicator shown=false).
	ConfirmErr   error
	NotifyErr    error
	IndicatorErr error

	Notifications []string
	Questions     []Question
	Indicators    []string
	Stopped       int
	end           chan struct{}
}

// NewFake returns a Fake where a user is present and answers yes.
func NewFake() *Fake { return &Fake{Answer: true, Asked: true, Shown: true} }

// Notify records the notification.
func (f *Fake) Notify(_ context.Context, title, message string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Notifications = append(f.Notifications, title+": "+message)
	return f.NotifyErr
}

// Confirm records the question and returns the scripted answer.
func (f *Fake) Confirm(ctx context.Context, q Question) (bool, bool, error) {
	f.mu.Lock()
	f.Questions = append(f.Questions, q)
	answer, asked, timesOut, cerr := f.Answer, f.Asked, f.TimesOut, f.ConfirmErr
	f.mu.Unlock()
	if cerr != nil {
		return false, false, cerr
	}
	if timesOut && asked {
		timeout := q.Timeout
		if timeout <= 0 {
			timeout = 60 * time.Second
		}
		t := time.NewTimer(timeout)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false, true, ctx.Err()
		case <-t.C:
			return q.DefaultYes, true, nil
		}
	}
	return answer, asked, nil
}

// ShowIndicator records the indicator.
func (f *Fake) ShowIndicator(_ context.Context, title, message string) (func(), <-chan struct{}, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Indicators = append(f.Indicators, title+": "+message)
	if f.IndicatorErr != nil {
		return func() {}, make(chan struct{}), false, f.IndicatorErr
	}
	f.end = make(chan struct{})
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.Stopped++
	}, f.end, f.Shown, nil
}

// Set changes the scripted behaviour while a test is running.
func (f *Fake) Set(change func(f *Fake)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

// UserEndsSession simulates the user clicking "End session" on the indicator.
func (f *Fake) UserEndsSession() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.end != nil {
		close(f.end)
		f.end = nil
	}
}

// Snapshot returns copies of what was recorded.
func (f *Fake) Snapshot() (notifications []string, questions []Question, indicators []string, stopped int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.Notifications...), append([]Question(nil), f.Questions...), append([]string(nil), f.Indicators...), f.Stopped
}
