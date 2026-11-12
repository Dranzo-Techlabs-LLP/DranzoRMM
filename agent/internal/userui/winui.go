package userui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// Windows implementation.
//
//   - Notify and Confirm: WTSSendMessageW shows a system message box on the
//     console user's desktop (the agent itself runs in session 0 and has no
//     desktop). Confirm waits for Yes / No with the question's timeout.
//   - Indicator: a small always-on-top window "Remote session active: ..."
//     with an "End session" button, drawn by Windows PowerShell (WinForms)
//     started in the user's session with the user's own token. Only the
//     PowerShell console is hidden; the indicator window is visible, has no
//     close or minimise box and stays on top.
//
// The PowerShell source is a constant read from standard input; title and
// message travel in environment variables. Nothing from the server is ever
// part of a command line or of script text.
//
// This file has no build tag so that the logic is unit-tested on every OS;
// the Win32 call lives in wts_windows.go and only new_windows.go selects it.

// Win32 MessageBox styles and results used with WTSSendMessageW.
const (
	mbOK              = 0x00000000
	mbYesNo           = 0x00000004
	mbIconQuestion    = 0x00000020
	mbIconInformation = 0x00000040
	mbDefButton2      = 0x00000100
	mbSystemModal     = 0x00001000
	mbSetForeground   = 0x00010000

	idYes     = 6
	idNo      = 7
	idTimeout = 32000
)

// Exit codes and the readiness marker of the indicator script.
const (
	winIndicatorEnded  = 100
	winIndicatorClosed = 101
	winIndicatorShown  = "dranzo-indicator-shown"
)

// messageBoxer shows a message box in an interactive session. With wait it
// blocks until the user answered or timeoutSeconds passed and returns the
// button id.
type messageBoxer interface {
	Send(sessionID uint32, title, text string, style, timeoutSeconds uint32, wait bool) (response uint32, err error)
}

// winIndicatorScript is fed to "powershell.exe -Command -" on standard
// input. Every statement is on one line because PowerShell executes standard
// input line by line. It is a constant: texts come from the environment.
const winIndicatorScript = `$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$global:dzEnded = $false
$global:dzOrphan = $false
$form = New-Object System.Windows.Forms.Form
$form.Text = $env:` + EnvTitle + `
$form.TopMost = $true
$form.ShowInTaskbar = $true
$form.ControlBox = $false
$form.MinimizeBox = $false
$form.MaximizeBox = $false
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
$form.ClientSize = New-Object System.Drawing.Size(400, 104)
$area = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$form.Location = New-Object System.Drawing.Point(($area.Right - $form.Width - 16), ($area.Top + 16))
$label = New-Object System.Windows.Forms.Label
$label.Text = $env:` + EnvMessage + `
$label.UseMnemonic = $false
$label.Location = New-Object System.Drawing.Point(12, 10)
$label.Size = New-Object System.Drawing.Size(376, 50)
$button = New-Object System.Windows.Forms.Button
$button.Text = $env:` + EnvEndLabel + `
$button.UseMnemonic = $false
$button.Location = New-Object System.Drawing.Point(268, 66)
$button.Size = New-Object System.Drawing.Size(120, 28)
$button.Add_Click({ $global:dzEnded = $true; $form.Close() })
$form.Controls.Add($label)
$form.Controls.Add($button)
$form.Add_FormClosing({ param($s, $e) if ((-not $global:dzEnded) -and (-not $global:dzOrphan) -and ($e.CloseReason -eq [System.Windows.Forms.CloseReason]::UserClosing)) { $e.Cancel = $true } })
$form.Add_Shown({ [Console]::Out.WriteLine('` + winIndicatorShown + `'); [Console]::Out.Flush() })
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 5000
$timer.Add_Tick({ if (-not (Get-Process -Id ([int]$env:` + EnvParentPID + `) -ErrorAction SilentlyContinue)) { $global:dzOrphan = $true; $form.Close() } })
$timer.Start()
[System.Windows.Forms.Application]::Run($form)
if ($global:dzEnded) { exit 100 } else { exit 101 }
`

// winIndicatorArgs are the PowerShell arguments: no profile, no prompt, the
// console window hidden, commands from standard input.
func winIndicatorArgs() []string {
	return []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", "-"}
}

// winIndicatorEnv carries the texts to the script.
func winIndicatorEnv(title, message string, parentPID int) []string {
	return []string{
		EnvTitle + "=" + title,
		EnvMessage + "=" + message,
		EnvEndLabel + "=" + EndSessionLabel,
		EnvParentPID + "=" + strconv.Itoa(parentPID),
	}
}

// winConfirmText adds what the fixed Yes / No buttons mean when the caller
// asked for other captions (a system message box cannot rename its buttons).
func winConfirmText(q Question) string {
	if q.YesLabel == defaultYesLabel && q.NoLabel == defaultNoLabel {
		return q.Message
	}
	return q.Message + "\n\nYes = " + q.YesLabel + "\nNo = " + q.NoLabel
}

func winConfirmStyle(q Question) uint32 {
	style := uint32(mbYesNo | mbIconQuestion | mbSystemModal | mbSetForeground)
	if !q.DefaultYes {
		style |= mbDefButton2
	}
	return style
}

type winUI struct {
	plat    platform.Platform
	msg     messageBoxer
	ps      func() string
	pid     int
	timings indicatorTimings
}

func newWinUI(plat platform.Platform, msg messageBoxer) *winUI {
	tm := defaultIndicatorTimings()
	// The script reports when the window is on screen.
	tm.presumeReady = 0
	return &winUI{plat: plat, msg: msg, ps: windowsPowerShell, pid: os.Getpid(), timings: tm}
}

// windowsPowerShell is Windows PowerShell 5.1, which ships with every
// supported Windows version.
func windowsPowerShell() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}

// Notify implements UI.
func (w *winUI) Notify(ctx context.Context, title, message string) error {
	u, err := consoleUser(ctx, w.plat)
	if err != nil || u == nil {
		return err
	}
	// Not waiting: the box closes by itself after the timeout.
	_, err = w.msg.Send(u.SessionID, cleanLine(title, maxTitleLen), cleanText(message, maxMessageLen),
		mbOK|mbIconInformation|mbSetForeground, uint32(notifyTimeout.Seconds()), false)
	if err != nil {
		return fmt.Errorf("show notification: %w", err)
	}
	return nil
}

// Confirm implements UI.
func (w *winUI) Confirm(ctx context.Context, q Question) (yes, asked bool, err error) {
	u, err := consoleUser(ctx, w.plat)
	if err != nil || u == nil {
		return false, false, err
	}
	q = normalize(q)
	type answer struct {
		response uint32
		err      error
	}
	done := make(chan answer, 1)
	secs := timeoutSeconds(q)
	go func() {
		// The Win32 call cannot be interrupted; it returns after at most
		// the timeout, so the goroutine is bounded.
		r, err := w.msg.Send(u.SessionID, q.Title, winConfirmText(q), winConfirmStyle(q), uint32(secs), true) //nolint:gosec // G115: secs is between 1 and 600
		done <- answer{r, err}
	}()
	select {
	case <-ctx.Done():
		return false, false, ctx.Err()
	case a := <-done:
		if a.err != nil {
			return false, false, fmt.Errorf("show prompt: %w", a.err)
		}
		switch a.response {
		case idYes:
			return true, true, nil
		case idNo:
			return false, true, nil
		case idTimeout:
			return q.DefaultYes, true, nil
		default:
			return false, false, fmt.Errorf("show prompt: unexpected message box result %d", a.response)
		}
	}
}

// ShowIndicator implements UI.
func (w *winUI) ShowIndicator(ctx context.Context, title, message string) (stop func(), ended <-chan struct{}, shown bool, err error) {
	title = cleanLine(title, maxTitleLen)
	// An environment variable cannot hold NUL; cleanText already removed it.
	message = cleanText(message, maxMessageLen)
	return runIndicator(ctx, w.plat, w.timings, func(ctx context.Context, u *platform.User, ready func()) (showResult, error) {
		var errb limitedBuffer
		code, err := w.plat.Run(ctx, platform.Command{
			Path:   w.ps(),
			Args:   winIndicatorArgs(),
			Env:    winIndicatorEnv(title, message, w.pid),
			Stdin:  strings.NewReader(winIndicatorScript),
			Stdout: &markerWriter{marker: winIndicatorShown, fn: ready},
			Stderr: &errb,
			AsUser: u,
		})
		if err != nil {
			return showClosed, fmt.Errorf("show indicator: %w", err)
		}
		if code == winIndicatorEnded {
			return showEnded, nil
		}
		// The window cannot be closed by the user: any other exit is a failure.
		if code == winIndicatorClosed {
			return showClosed, errors.New("show indicator: the indicator window closed")
		}
		return showClosed, fmt.Errorf("show indicator: powershell exit code %d: %s", code, firstLine(errb.String()))
	})
}
