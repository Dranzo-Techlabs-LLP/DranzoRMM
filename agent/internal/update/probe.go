package update

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/platform"
)

const (
	probeTimeout   = 15 * time.Second
	probeMaxOutput = 4 << 10
	// programName is the first word of "dranzo-agent version".
	programName = "dranzo-agent"
)

// limitedBuffer keeps at most max bytes and silently drops the rest.
type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

// ParseVersionOutput extracts the version from the output of
// "dranzo-agent version": "dranzo-agent <version> (<os>)".
func ParseVersionOutput(out string) (string, error) {
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != programName {
		return "", errors.New("unexpected output of the version command")
	}
	if len(fields) >= 3 {
		if os := strings.Trim(fields[2], "()"); os != platform.OSFamily {
			return "", fmt.Errorf("the binary is built for %q, not %q", clip(os), platform.OSFamily)
		}
	}
	return fields[1], nil
}

// ProbeVersion runs "<path> version" with a short timeout and returns the
// version the binary reports. The caller has already verified that path is
// the binary named by the signed command; the probe proves that it starts
// on this machine and is the release it claims to be.
func ProbeVersion(ctx context.Context, plat platform.Platform, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	out := &limitedBuffer{max: probeMaxOutput}
	code, err := plat.Run(ctx, platform.Command{
		Path:   path,
		Args:   []string{"version"},
		Dir:    filepath.Dir(path),
		Stdout: out,
		Stderr: io.Discard,
	})
	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("the version command did not finish within %s", probeTimeout)
		}
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("the version command exited with code %d", code)
	}
	return ParseVersionOutput(out.buf.String())
}
