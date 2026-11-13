//go:build darwin

package wifi

import (
	"context"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

type darwinEnroller struct{}

// NewEnroller: macOS installs 802.1X profiles only through a configuration
// profile the user approves (or MDM); see docs/MDM_PLAN.md.
func NewEnroller(platform.Platform, string) Enroller { return darwinEnroller{} }

func (darwinEnroller) RequestCSR(context.Context) (string, error)            { return "", ErrUnsupported }
func (darwinEnroller) Install(context.Context, string, string, string) error { return ErrUnsupported }
func (darwinEnroller) Remove(context.Context, string) error                  { return ErrUnsupported }
