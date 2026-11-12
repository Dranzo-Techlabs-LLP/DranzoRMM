package update

import (
	"os"
	"strings"
	"testing"
	"time"
)

func (e *env) guard() (bool, error) {
	aside := e.aside
	return Guard(GuardOptions{
		StateDir:    e.stateDir,
		checkExe:    fakeCheckExe,
		renameAside: &aside,
		failpoint:   e.point,
		now: func() time.Time {
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.now
		},
	})
}

func TestGuardWithoutPendingUpdate(t *testing.T) {
	e := newEnv(t, "1.0.0")
	if rolled, err := e.guard(); rolled || err != nil {
		t.Fatalf("no state: %v, %v", rolled, err)
	}
	if _, err := Guard(GuardOptions{}); err == nil {
		t.Fatal("no state directory accepted")
	}
	// A confirmed update that only awaits its report is none of the guard's business.
	e.installTo("2.0.0")
	u := e.boot()
	e.sender.setDown(true)
	u.onHello()
	for i := 0; i < 10; i++ {
		if rolled, err := e.guard(); rolled || err != nil {
			t.Fatalf("confirmed update: %v, %v", rolled, err)
		}
	}
	if e.installed() != "2.0.0" {
		t.Fatal("the guard rolled back a confirmed update")
	}
}

// A new binary that dies before it reaches the agent's own start-up code
// never counts its starts. The guard, run from the previous binary before
// each start of the service, counts for it and rolls back.
func TestGuardRollsBackABinaryThatNeverStarts(t *testing.T) {
	e := newEnv(t, "1.0.0")
	e.installTo("2.0.0")
	for run := 1; run <= DefaultMaxStarts; run++ {
		rolled, err := e.guard()
		if rolled || err != nil {
			t.Fatalf("run %d: %v, %v", run, rolled, err)
		}
		if st := e.state(); st.GuardRuns != run || st.Phase != phaseSwapping {
			t.Fatalf("run %d: state %+v", run, st)
		}
		if e.installed() != "2.0.0" {
			t.Fatalf("rolled back too early, at run %d", run)
		}
	}
	rolled, err := e.guard()
	if !rolled || err != nil {
		t.Fatalf("fourth run: %v, %v", rolled, err)
	}
	// Further runs change nothing.
	if rolled, err := e.guard(); rolled || err != nil {
		t.Fatalf("run after the rollback: %v, %v", rolled, err)
	}
	e.assertRolledBack("still unconfirmed after 3 checks by the update guard")
}

// With the guard in place and a new binary that does start, both count the
// same starts; whoever reaches the limit first rolls back, exactly once.
func TestGuardAndAgentCountTogether(t *testing.T) {
	e := newEnv(t, "1.0.0")
	e.installTo("2.0.0")
	for start := 1; start <= DefaultMaxStarts; start++ {
		if rolled, err := e.guard(); rolled || err != nil {
			t.Fatalf("start %d: guard %v, %v", start, rolled, err)
		}
		e.boot()
		if st := e.state(); st.Attempt != start || st.GuardRuns != start {
			t.Fatalf("start %d: state %+v", start, st)
		}
	}
	if rolled, err := e.guard(); !rolled || err != nil {
		t.Fatalf("guard: %v, %v", rolled, err)
	}
	e.assertRolledBack("update guard")
}

func TestGuardLeavesAConfirmingVersionAlone(t *testing.T) {
	e := newEnv(t, "1.0.0")
	e.installTo("2.0.0")
	if rolled, err := e.guard(); rolled || err != nil {
		t.Fatal(rolled, err)
	}
	u := e.boot()
	u.onHello()
	e.wantStates("2.0.0:installed")
	for i := 0; i < 10; i++ {
		if rolled, err := e.guard(); rolled || err != nil {
			t.Fatal(rolled, err)
		}
	}
	if e.installed() != "2.0.0" || len(e.failedVersions()) != 0 {
		t.Fatal("the guard touched a confirmed version")
	}
}

func TestGuardCompletesAnInterruptedRollback(t *testing.T) {
	e := newEnv(t, "1.0.0")
	e.installTo("2.0.0")
	u := e.boot()
	if !e.crash("rollback:failed-recorded", func() { u.rollback("the watchdog expired") }) {
		t.Fatal("point not reached")
	}
	if e.installed() != "2.0.0" {
		t.Fatal("unexpected state")
	}
	if rolled, err := e.guard(); !rolled || err != nil {
		t.Fatalf("guard: %v, %v", rolled, err)
	}
	e.assertRolledBack("the watchdog expired")
}

func TestGuardWithoutPreviousBinary(t *testing.T) {
	e := newEnv(t, "1.0.0")
	e.installTo("2.0.0")
	if err := os.Remove(e.paths().previous()); err != nil {
		t.Fatal(err)
	}
	var err error
	for i := 0; i <= DefaultMaxStarts; i++ {
		_, err = e.guard()
	}
	if err == nil || !strings.Contains(err.Error(), "not usable") {
		t.Fatalf("error: %v", err)
	}
	if st := e.state(); !st.NoRollback || e.installed() != "2.0.0" {
		t.Fatalf("state %+v", st)
	}
	// Given up for good: no error, no action on later runs.
	if rolled, err := e.guard(); rolled || err != nil {
		t.Fatalf("later run: %v, %v", rolled, err)
	}
}
