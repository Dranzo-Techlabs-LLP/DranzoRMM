package platform

import (
	"context"
	"sync"
)

// Fake is a Platform for tests. Commands run through the real OS
// implementation (as the current user) unless RunFunc is set; everything else
// is answered from the struct fields.
type Fake struct {
	mu sync.Mutex

	User          *User // nil means nobody is logged in
	Users         []string
	Reboot        bool
	ID            string
	RunFunc       func(ctx context.Context, cmd Command) (int, error)
	GrantFunc     func(path string, u *User) error
	IgnoreAsUser  bool // run AsUser commands as the current user (tests cannot switch users)
	Granted       []string
	RanAsUser     int
	real          Platform
	realInitOnce  sync.Once
	ConsoleErr    error
	PendingErr    error
	MachineIDErr  error
	LoggedInError error
}

func (f *Fake) native() Platform {
	f.realInitOnce.Do(func() { f.real = New() })
	return f.real
}

// ConsoleUser implements Platform.
func (f *Fake) ConsoleUser(context.Context) (*User, error) {
	if f.ConsoleErr != nil {
		return nil, f.ConsoleErr
	}
	if f.User == nil {
		return nil, ErrNoConsoleUser
	}
	u := *f.User
	return &u, nil
}

// LoggedInUsers implements Platform.
func (f *Fake) LoggedInUsers(context.Context) ([]string, error) {
	return f.Users, f.LoggedInError
}

// Run implements Platform.
func (f *Fake) Run(ctx context.Context, cmd Command) (int, error) {
	if cmd.AsUser != nil {
		f.mu.Lock()
		f.RanAsUser++
		f.mu.Unlock()
		if f.IgnoreAsUser {
			cmd.AsUser = nil
		}
	}
	if f.RunFunc != nil {
		return f.RunFunc(ctx, cmd)
	}
	return f.native().Run(ctx, cmd)
}

// GrantUser implements Platform.
func (f *Fake) GrantUser(path string, u *User) error {
	f.mu.Lock()
	f.Granted = append(f.Granted, path)
	f.mu.Unlock()
	if f.GrantFunc != nil {
		return f.GrantFunc(path, u)
	}
	return nil
}

// PendingReboot implements Platform.
func (f *Fake) PendingReboot(context.Context) (bool, error) { return f.Reboot, f.PendingErr }

// MachineID implements Platform.
func (f *Fake) MachineID(context.Context) (string, error) { return f.ID, f.MachineIDErr }
