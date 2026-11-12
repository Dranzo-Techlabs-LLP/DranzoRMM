//go:build windows

package userui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

// Live Windows UI test (DRANZO_REAL_WINDOWS=1 and DRANZO_REAL_WINDOWS_UI=1,
// run by the Windows verification kit with -Ui). A PERSON must sit at the
// VM's console, signed in, and follow the instructions in the kit window.
// It needs LocalSystem (the agent shows its UI in the console user's session
// through WTSQueryUserToken); the kit runs this package as SYSTEM.
//
// Nothing is changed on the machine: message boxes and a small window.

func requireUITest(t *testing.T) {
	t.Helper()
	if os.Getenv("DRANZO_REAL_WINDOWS") != "1" || os.Getenv("DRANZO_REAL_WINDOWS_UI") != "1" {
		t.Skip("set DRANZO_REAL_WINDOWS=1 and DRANZO_REAL_WINDOWS_UI=1 (someone must be at the console)")
	}
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !tu.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("the UI test needs LocalSystem, like the agent service (the kit runs it as SYSTEM with -Ui)")
	}
}

// say prints an instruction for the person at the console (the kit window
// shows this log live).
func say(t *testing.T, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	t.Logf("\n\n>>>>> ACTION FOR THE PERSON AT THE VM: %s\n", msg)
	fmt.Printf("\n>>>>> ACTION FOR THE PERSON AT THE VM: %s\n\n", msg)
}

func TestWindowsLiveUI(t *testing.T) {
	requireUITest(t)
	plat := platform.New()
	u, err := plat.ConsoleUser(context.Background())
	if errors.Is(err, platform.ErrNoConsoleUser) {
		t.Fatal("nobody is signed in at the console: sign in on the VM and run the kit again")
	}
	if err != nil {
		t.Fatalf("console user: %v", err)
	}
	t.Logf("console user: %+v", *u)
	ui := New(plat)
	ctx := context.Background()

	ask := func(title, message string, timeout time.Duration, defaultYes bool) (yes, asked bool) {
		t.Helper()
		yes, asked, err := ui.Confirm(ctx, Question{Title: title, Message: message, Timeout: timeout, DefaultYes: defaultYes})
		t.Logf("Confirm(%q): yes=%v asked=%v err=%v", title, yes, asked, err)
		if err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		return yes, asked
	}

	t.Run("notify", func(t *testing.T) {
		say(t, "a message box \"DranzoRMM kit: notification\" appears for 20 seconds. Just look at it (do not need to click). Then answer the next question.")
		if err := ui.Notify(ctx, "DranzoRMM kit: notification", "This is a test notification from the DranzoRMM Windows verification kit."); err != nil {
			t.Fatalf("Notify: %v", err)
		}
		time.Sleep(3 * time.Second)
		say(t, "a question \"Did you see the notification?\" appears: click YES if you saw it, NO if not.")
		yes, asked := ask("DranzoRMM kit: question 1", "Did you see the message box \"DranzoRMM kit: notification\"?\n\nClick Yes if you saw it.", 3*time.Minute, false)
		if !asked || !yes {
			t.Errorf("the person did not confirm the notification (yes=%v asked=%v)", yes, asked)
		}
	})

	t.Run("confirm-no", func(t *testing.T) {
		say(t, "a question appears: click NO now.")
		yes, asked := ask("DranzoRMM kit: question 2", "Please click No.", 3*time.Minute, true)
		if !asked || yes {
			t.Errorf("expected the answer No (yes=%v asked=%v)", yes, asked)
		}
	})

	t.Run("confirm-timeout", func(t *testing.T) {
		say(t, "a question appears: do NOT click anything, wait 20 seconds until it closes by itself.")
		start := time.Now()
		yes, asked := ask("DranzoRMM kit: question 3", "Please do not click. This box closes by itself after 20 seconds.", 20*time.Second, true)
		took := time.Since(start)
		t.Logf("timed out after %v", took)
		if !asked || !yes || took < 15*time.Second {
			t.Errorf("unanswered question: yes=%v asked=%v after %v; want the default (yes) after the timeout", yes, asked, took)
		}
	})

	t.Run("indicator-end-button", func(t *testing.T) {
		say(t, "a small always-on-top window \"DranzoRMM kit: remote session\" appears at the top right. Click its \"End session\" button.")
		stop, ended, shown, err := ui.ShowIndicator(ctx, "DranzoRMM kit: remote session", "Remote session active: Windows verification kit. Click \"End session\" to end it.")
		if err != nil || !shown {
			t.Fatalf("ShowIndicator: shown=%v err=%v", shown, err)
		}
		defer stop()
		select {
		case <-ended:
			t.Log("the person ended the session from the indicator")
		case <-time.After(3 * time.Minute):
			t.Fatal("the indicator's End session button was not clicked within 3 minutes (or the click was not reported)")
		}
	})

	t.Run("indicator-stop", func(t *testing.T) {
		say(t, "the indicator window appears again and closes by itself after 10 seconds. Do not click it.")
		stop, ended, shown, err := ui.ShowIndicator(ctx, "DranzoRMM kit: remote session", "Remote session active: Windows verification kit. This window closes by itself.")
		if err != nil || !shown {
			t.Fatalf("ShowIndicator: shown=%v err=%v", shown, err)
		}
		time.Sleep(10 * time.Second)
		select {
		case <-ended:
			t.Error("the indicator reported End session without a click")
		default:
		}
		stop()
		time.Sleep(2 * time.Second)
		say(t, "a question appears: click YES if the indicator window has disappeared.")
		yes, asked := ask("DranzoRMM kit: question 4", "Has the \"DranzoRMM kit: remote session\" window disappeared?", 3*time.Minute, false)
		if !asked || !yes {
			t.Errorf("the indicator did not disappear after stop (yes=%v asked=%v)", yes, asked)
		}
	})
}
