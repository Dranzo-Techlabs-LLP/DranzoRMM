// Package platform contains the per-OS helpers of the agent behind small
// interfaces so they can be faked in tests: console / logged-in user lookup,
// running a command as the system or as the console user, process-tree kill,
// pending-reboot detection and the machine id.
//
// OS-specific code lives in *_windows.go, *_darwin.go and *_linux.go files;
// parsing of command output lives in untagged files so it is unit-tested on
// every OS.
package platform

import (
	"context"
	"errors"
	"io"
)

// ErrNoConsoleUser is returned when nobody is logged in at the console.
var ErrNoConsoleUser = errors.New("no logged-in user")

// ErrUnsupported marks a feature the current OS cannot provide. Callers turn
// it into the "unsupported" job status ("not supported on this OS: ...").
var ErrUnsupported = errors.New("not supported on this OS")

// User identifies a local account / interactive session.
type User struct {
	// Name is the account name (Windows: DOMAIN\user).
	Name string
	// UID and GID are the numeric ids on Unix (empty on Windows).
	UID string
	GID string
	// Home is the home directory (may be empty).
	Home string
	// Shell is the login shell on Unix (may be empty).
	Shell string
	// SID and SessionID identify the user and the interactive session on Windows.
	SID       string
	SessionID uint32
}

// Command describes a process to run. Arguments are always passed as an argv
// array; nothing is ever interpreted by a shell.
type Command struct {
	Path string
	// Args are the arguments after the program name.
	Args []string
	// Env holds extra KEY=VALUE variables added to the base environment (the
	// agent's own for system commands, the user's for AsUser commands).
	Env []string
	// Dir is the working directory ("" keeps the default).
	Dir    string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// AsUser runs the command in that user's session; nil runs it as the
	// agent itself (root / LocalSystem).
	AsUser *User
}

// Platform is the set of OS services used by the agent core, the job
// handlers and the inventory collector.
type Platform interface {
	// ConsoleUser returns the user logged in at the console (the active
	// interactive session), or ErrNoConsoleUser.
	ConsoleUser(ctx context.Context) (*User, error)
	// LoggedInUsers lists the names of all users with a login session.
	LoggedInUsers(ctx context.Context) ([]string, error)
	// Run executes cmd and waits for it. It returns the exit code when the
	// process ran to completion. If ctx ends first the whole process tree is
	// killed and ctx's error is returned.
	Run(ctx context.Context, cmd Command) (exitCode int, err error)
	// GrantUser makes path (a file or directory created by the agent)
	// accessible to u, and only to u besides the system itself.
	GrantUser(path string, u *User) error
	// PendingReboot reports whether the OS is waiting for a restart.
	PendingReboot(ctx context.Context) (bool, error)
	// MachineID returns the stable OS machine identifier.
	MachineID(ctx context.Context) (string, error)
}

// New returns the Platform implementation for the OS this binary was built for.
func New() Platform { return newNative() }

// ExitCodeUnknown is returned as exit code when a process did not run to completion.
const ExitCodeUnknown = -1
