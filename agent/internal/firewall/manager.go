package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/fsutil"
)

// Backend reads and replaces the rules the agent owns in the OS firewall.
type Backend interface {
	// Owned returns the IDs of the rules in place.
	Owned(ctx context.Context) ([]string, error)
	// Apply replaces every owned rule with rules (nil removes them all).
	Apply(ctx context.Context, rules []Rule) error
}

// ErrUnsupported is returned by a backend that cannot run here (for example
// no nft on Linux).
var ErrUnsupported = errors.New("firewall rules are not supported here")

// Manager applies rules with a safety net: when the server cannot be reached
// afterwards, the previous rules are restored.
type Manager struct {
	Backend Backend
	// StatePath keeps the last applied rules, for rollback and re-applying.
	StatePath string
	// Reachable checks that the DranzoRMM server can still be reached.
	Reachable func(ctx context.Context) error
	// ReachTimeout bounds the reachability check (default 30 s).
	ReachTimeout time.Duration
}

// Owned returns the IDs of the rules in place.
func (m *Manager) Owned(ctx context.Context) ([]string, error) { return m.Backend.Owned(ctx) }

// Enforce replaces the owned rules with rules, checks that the server is still
// reachable and rolls back if not.
func (m *Manager) Enforce(ctx context.Context, rules []Rule) error {
	prev := m.load()
	if err := m.Backend.Apply(ctx, rules); err != nil {
		return err
	}
	if m.Reachable != nil {
		timeout := m.ReachTimeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		rctx, cancel := context.WithTimeout(ctx, timeout)
		err := m.Reachable(rctx)
		cancel()
		if err != nil {
			if rbErr := m.Backend.Apply(ctx, prev); rbErr != nil {
				return fmt.Errorf("the server was unreachable after applying the rules (%w) and restoring the previous rules failed: %w", err, rbErr)
			}
			return fmt.Errorf("the server was unreachable after applying the rules, so the previous rules were restored: %w", err)
		}
	}
	return m.save(rules)
}

// Clear removes every owned rule (uninstall, or a policy that no longer applies).
func (m *Manager) Clear(ctx context.Context) error {
	if err := m.Backend.Apply(ctx, nil); err != nil {
		return err
	}
	if m.StatePath != "" {
		if err := os.Remove(m.StatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (m *Manager) load() []Rule {
	if m.StatePath == "" {
		return nil
	}
	b, err := os.ReadFile(m.StatePath)
	if err != nil {
		return nil
	}
	var rules []Rule
	if json.Unmarshal(b, &rules) != nil {
		return nil
	}
	return rules
}

func (m *Manager) save(rules []Rule) error {
	if m.StatePath == "" {
		return nil
	}
	b, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(m.StatePath, b)
}
