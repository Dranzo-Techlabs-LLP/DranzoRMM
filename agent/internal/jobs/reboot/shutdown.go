package reboot

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
	"github.com/dranzo/dranzormm/agent/internal/software"
)

// UnixShutdownArgs builds the arguments of "shutdown -r +M [message]"
// (macOS and Linux). shutdown counts in minutes, so a delay is rounded up to
// the next full minute; zero is "now".
func UnixShutdownArgs(delay time.Duration, message string) []string {
	when := "now"
	if delay > 0 {
		minutes := int64((delay + time.Minute - 1) / time.Minute)
		when = "+" + strconv.FormatInt(minutes, 10)
	}
	args := []string{"-r", when}
	if message = strings.TrimSpace(message); message != "" {
		args = append(args, message)
	}
	return args
}

// WindowsShutdownArgs builds the arguments of
// "shutdown.exe /r /t N [/c message]".
func WindowsShutdownArgs(delay time.Duration, message string) []string {
	seconds := int64(0)
	if delay > 0 {
		seconds = int64((delay + time.Second - 1) / time.Second)
	}
	args := []string{"/r", "/t", strconv.FormatInt(seconds, 10)}
	if message = strings.TrimSpace(message); message != "" {
		args = append(args, "/c", message)
	}
	return args
}

// ShutdownRebooter restarts the machine with the operating system's
// shutdown tool.
type ShutdownRebooter struct {
	Plat platform.Platform
	// Lookup resolves "shutdown" to its absolute path.
	Lookup software.Lookup
	// Args builds the tool's arguments (UnixShutdownArgs or WindowsShutdownArgs).
	Args func(delay time.Duration, message string) []string
}

// Reboot implements Rebooter.
func (r *ShutdownRebooter) Reboot(ctx context.Context, delay time.Duration, message string) error {
	if err := ValidMessage(message); err != nil {
		return err
	}
	shutdown := r.Lookup("shutdown")
	if shutdown == "" {
		return fmt.Errorf("%w: restart needs the shutdown tool, which is not installed", platform.ErrUnsupported)
	}
	res, err := software.Output(ctx, r.Plat, time.Minute, platform.Command{Path: shutdown, Args: r.Args(delay, message)})
	if err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("shutdown exited with code %d: %s", res.ExitCode, software.Clean(res.Stderr, 300))
	}
	return nil
}
