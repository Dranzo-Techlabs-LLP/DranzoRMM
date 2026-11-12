package update

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrNotExecutable is returned when a staged file is not a native executable
// for the operating system and CPU architecture of this agent.
var ErrNotExecutable = errors.New("not an executable for this platform")

// Header constants of the three executable formats.
const (
	elfClass64   = 2
	elfDataLE    = 1
	elfTypeExec  = 2
	elfTypeDyn   = 3 // position-independent executables
	elfMachX8664 = 62
	elfMachARM64 = 183

	peMachAMD64     = 0x8664
	peMachARM64     = 0xAA64
	peCharExecImage = 0x0002
	peCharDLL       = 0x2000
	peOptMagic64    = 0x20B

	machoMagic64     = 0xFEEDFACF // thin, 64-bit, read little-endian
	machoFatMagic    = 0xCAFEBABE // universal, read big-endian
	machoFatMagic64  = 0xCAFEBABF
	machoCPUX8664    = 0x01000007
	machoCPUARM64    = 0x0100000C
	machoTypeExecute = 2
	machoMaxFatArchs = 16
)

func notExecutable(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrNotExecutable, fmt.Sprintf(format, args...))
}

// readAt reads exactly n bytes at off; a short file is "not executable".
func readAt(r io.ReaderAt, off int64, n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := r.ReadAt(buf, off); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, notExecutable("file is truncated")
		}
		return nil, err
	}
	return buf, nil
}

// CheckExecutable verifies from the file headers that r is a native 64-bit
// executable for goos ("windows", "darwin", "linux") and goarch ("amd64",
// "arm64"): PE, Mach-O (thin or universal with a matching slice) or ELF with
// the matching machine type. It is a sanity check against shipping the wrong
// artefact, not a security control: authenticity comes from the signed SHA-256.
func CheckExecutable(r io.ReaderAt, goos, goarch string) error {
	if goarch != "amd64" && goarch != "arm64" {
		return fmt.Errorf("unsupported architecture %q", goarch)
	}
	switch goos {
	case "linux":
		return checkELF(r, goarch)
	case "windows":
		return checkPE(r, goarch)
	case "darwin":
		return checkMachO(r, goarch)
	default:
		return fmt.Errorf("unsupported operating system %q", goos)
	}
}

// CheckExecutableFile is CheckExecutable for a regular file on disk.
func CheckExecutableFile(path, goos, goarch string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return notExecutable("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return CheckExecutable(f, goos, goarch)
}

func checkELF(r io.ReaderAt, goarch string) error {
	h, err := readAt(r, 0, 20)
	if err != nil {
		return err
	}
	if h[0] != 0x7F || h[1] != 'E' || h[2] != 'L' || h[3] != 'F' {
		return notExecutable("not an ELF file")
	}
	if h[4] != elfClass64 || h[5] != elfDataLE {
		return notExecutable("ELF file is not 64-bit little-endian")
	}
	if t := binary.LittleEndian.Uint16(h[16:]); t != elfTypeExec && t != elfTypeDyn {
		return notExecutable("ELF type %d is not an executable", t)
	}
	want := uint16(elfMachX8664)
	if goarch == "arm64" {
		want = elfMachARM64
	}
	if m := binary.LittleEndian.Uint16(h[18:]); m != want {
		return notExecutable("ELF machine %d does not match %s", m, goarch)
	}
	return nil
}

func checkPE(r io.ReaderAt, goarch string) error {
	dos, err := readAt(r, 0, 0x40)
	if err != nil {
		return err
	}
	if dos[0] != 'M' || dos[1] != 'Z' {
		return notExecutable("not a PE file")
	}
	off := int64(binary.LittleEndian.Uint32(dos[0x3C:]))
	if off < 0x40 || off > 1<<20 {
		return notExecutable("implausible PE header offset")
	}
	// Signature (4) + COFF file header (20) + optional header magic (2).
	h, err := readAt(r, off, 26)
	if err != nil {
		return err
	}
	if h[0] != 'P' || h[1] != 'E' || h[2] != 0 || h[3] != 0 {
		return notExecutable("PE signature missing")
	}
	want := uint16(peMachAMD64)
	if goarch == "arm64" {
		want = peMachARM64
	}
	if m := binary.LittleEndian.Uint16(h[4:]); m != want {
		return notExecutable("PE machine 0x%04x does not match %s", m, goarch)
	}
	if c := binary.LittleEndian.Uint16(h[22:]); c&peCharExecImage == 0 || c&peCharDLL != 0 {
		return notExecutable("PE file is not an executable image")
	}
	if m := binary.LittleEndian.Uint16(h[24:]); m != peOptMagic64 {
		return notExecutable("PE file is not PE32+")
	}
	return nil
}

func machoCPU(goarch string) uint32 {
	if goarch == "arm64" {
		return machoCPUARM64
	}
	return machoCPUX8664
}

// checkMachOThin checks a thin 64-bit Mach-O header at off.
func checkMachOThin(r io.ReaderAt, off int64, goarch string) error {
	h, err := readAt(r, off, 16)
	if err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(h) != machoMagic64 {
		return notExecutable("not a 64-bit Mach-O file")
	}
	if cpu := binary.LittleEndian.Uint32(h[4:]); cpu != machoCPU(goarch) {
		return notExecutable("Mach-O CPU type 0x%08x does not match %s", cpu, goarch)
	}
	if t := binary.LittleEndian.Uint32(h[12:]); t != machoTypeExecute {
		return notExecutable("Mach-O file type %d is not an executable", t)
	}
	return nil
}

func checkMachO(r io.ReaderAt, goarch string) error {
	h, err := readAt(r, 0, 8)
	if err != nil {
		return err
	}
	magic := binary.BigEndian.Uint32(h)
	if magic != machoFatMagic && magic != machoFatMagic64 {
		return checkMachOThin(r, 0, goarch)
	}
	// Universal binary: big-endian table of slices; one must match.
	n := binary.BigEndian.Uint32(h[4:])
	if n == 0 || n > machoMaxFatArchs {
		// Java class files share the 0xCAFEBABE magic; their "count" is a
		// class-file version, far above any real slice count.
		return notExecutable("implausible universal binary slice count %d", n)
	}
	entry := 20
	if magic == machoFatMagic64 {
		entry = 32
	}
	for i := 0; i < int(n); i++ {
		e, err := readAt(r, int64(8+i*entry), entry)
		if err != nil {
			return err
		}
		if binary.BigEndian.Uint32(e) != machoCPU(goarch) {
			continue
		}
		var off uint64
		if magic == machoFatMagic64 {
			off = binary.BigEndian.Uint64(e[8:])
		} else {
			off = uint64(binary.BigEndian.Uint32(e[8:]))
		}
		if off > 1<<40 {
			return notExecutable("implausible universal binary slice offset")
		}
		return checkMachOThin(r, int64(off), goarch)
	}
	return notExecutable("universal binary has no %s slice", goarch)
}
