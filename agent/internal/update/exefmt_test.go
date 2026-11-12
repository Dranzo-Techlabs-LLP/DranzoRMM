package update

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// ---- minimal fixture headers ----

func elfHeader(class, data byte, typ, machine uint16) []byte {
	h := make([]byte, 64)
	copy(h, []byte{0x7F, 'E', 'L', 'F', class, data, 1})
	binary.LittleEndian.PutUint16(h[16:], typ)
	binary.LittleEndian.PutUint16(h[18:], machine)
	return h
}

func peHeader(machine, characteristics, optMagic uint16) []byte {
	const off = 0x80
	h := make([]byte, off+64)
	copy(h, "MZ")
	binary.LittleEndian.PutUint32(h[0x3C:], off)
	copy(h[off:], []byte{'P', 'E', 0, 0})
	binary.LittleEndian.PutUint16(h[off+4:], machine)
	binary.LittleEndian.PutUint16(h[off+22:], characteristics)
	binary.LittleEndian.PutUint16(h[off+24:], optMagic)
	return h
}

func machoHeader(cpu, filetype uint32) []byte {
	h := make([]byte, 32)
	binary.LittleEndian.PutUint32(h, machoMagic64)
	binary.LittleEndian.PutUint32(h[4:], cpu)
	binary.LittleEndian.PutUint32(h[12:], filetype)
	return h
}

// fatBinary builds a universal binary with one thin slice per CPU type.
func fatBinary(fat64 bool, cpus ...uint32) []byte {
	entry := 20
	magic := uint32(machoFatMagic)
	if fat64 {
		entry, magic = 32, machoFatMagic64
	}
	const sliceStart, sliceSize = 4096, 64
	out := make([]byte, sliceStart+sliceSize*len(cpus))
	binary.BigEndian.PutUint32(out, magic)
	binary.BigEndian.PutUint32(out[4:], uint32(len(cpus)))
	for i, cpu := range cpus {
		e := out[8+i*entry:]
		off := sliceStart + i*sliceSize
		binary.BigEndian.PutUint32(e, cpu)
		if fat64 {
			binary.BigEndian.PutUint64(e[8:], uint64(off))
			binary.BigEndian.PutUint64(e[16:], sliceSize)
		} else {
			binary.BigEndian.PutUint32(e[8:], uint32(off))
			binary.BigEndian.PutUint32(e[12:], sliceSize)
		}
		copy(out[off:], machoHeader(cpu, machoTypeExecute))
	}
	return out
}

func TestCheckExecutable(t *testing.T) {
	const exeChars = peCharExecImage | 0x0020
	javaClass := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x41, 0, 0, 0, 0}
	cases := []struct {
		name         string
		data         []byte
		goos, goarch string
		ok           bool
	}{
		// ELF
		{"elf amd64 exec", elfHeader(2, 1, elfTypeExec, elfMachX8664), "linux", "amd64", true},
		{"elf arm64 exec", elfHeader(2, 1, elfTypeExec, elfMachARM64), "linux", "arm64", true},
		{"elf arm64 pie", elfHeader(2, 1, elfTypeDyn, elfMachARM64), "linux", "arm64", true},
		{"elf wrong arch (arm64 on amd64)", elfHeader(2, 1, elfTypeExec, elfMachARM64), "linux", "amd64", false},
		{"elf wrong arch (amd64 on arm64)", elfHeader(2, 1, elfTypeExec, elfMachX8664), "linux", "arm64", false},
		{"elf 32-bit", elfHeader(1, 1, elfTypeExec, 3), "linux", "amd64", false},
		{"elf big-endian", elfHeader(2, 2, elfTypeExec, elfMachX8664), "linux", "amd64", false},
		{"elf relocatable object", elfHeader(2, 1, 1, elfMachX8664), "linux", "amd64", false},
		{"elf core dump", elfHeader(2, 1, 4, elfMachX8664), "linux", "amd64", false},
		{"elf truncated", elfHeader(2, 1, elfTypeExec, elfMachX8664)[:10], "linux", "amd64", false},
		{"elf on windows", elfHeader(2, 1, elfTypeExec, elfMachX8664), "windows", "amd64", false},
		{"elf on darwin", elfHeader(2, 1, elfTypeExec, elfMachARM64), "darwin", "arm64", false},
		// PE
		{"pe amd64", peHeader(peMachAMD64, exeChars, peOptMagic64), "windows", "amd64", true},
		{"pe arm64", peHeader(peMachARM64, exeChars, peOptMagic64), "windows", "arm64", true},
		{"pe wrong arch (arm64 on amd64)", peHeader(peMachARM64, exeChars, peOptMagic64), "windows", "amd64", false},
		{"pe wrong arch (amd64 on arm64)", peHeader(peMachAMD64, exeChars, peOptMagic64), "windows", "arm64", false},
		{"pe i386", peHeader(0x014C, exeChars, 0x10B), "windows", "amd64", false},
		{"pe dll", peHeader(peMachAMD64, exeChars|peCharDLL, peOptMagic64), "windows", "amd64", false},
		{"pe object (not an image)", peHeader(peMachAMD64, 0, peOptMagic64), "windows", "amd64", false},
		{"pe 32-bit optional header", peHeader(peMachAMD64, exeChars, 0x10B), "windows", "amd64", false},
		{"pe truncated", peHeader(peMachAMD64, exeChars, peOptMagic64)[:0x80], "windows", "amd64", false},
		{"pe header offset out of range", append([]byte("MZ"), bytes.Repeat([]byte{0xFF}, 0x3E)...), "windows", "amd64", false},
		{"dos stub only", append([]byte("MZ"), make([]byte, 0x3E)...), "windows", "amd64", false},
		{"pe on linux", peHeader(peMachAMD64, exeChars, peOptMagic64), "linux", "amd64", false},
		// Mach-O
		{"macho arm64", machoHeader(machoCPUARM64, machoTypeExecute), "darwin", "arm64", true},
		{"macho amd64", machoHeader(machoCPUX8664, machoTypeExecute), "darwin", "amd64", true},
		{"macho wrong arch (amd64 on arm64)", machoHeader(machoCPUX8664, machoTypeExecute), "darwin", "arm64", false},
		{"macho wrong arch (arm64 on amd64)", machoHeader(machoCPUARM64, machoTypeExecute), "darwin", "amd64", false},
		{"macho dylib", machoHeader(machoCPUARM64, 6), "darwin", "arm64", false},
		{"macho truncated", machoHeader(machoCPUARM64, machoTypeExecute)[:8], "darwin", "arm64", false},
		{"macho universal, arm64 wanted", fatBinary(false, machoCPUX8664, machoCPUARM64), "darwin", "arm64", true},
		{"macho universal, amd64 wanted", fatBinary(false, machoCPUX8664, machoCPUARM64), "darwin", "amd64", true},
		{"macho universal 64", fatBinary(true, machoCPUX8664, machoCPUARM64), "darwin", "arm64", true},
		{"macho universal without our slice", fatBinary(false, machoCPUX8664), "darwin", "arm64", false},
		{"macho universal, slice table truncated", fatBinary(false, machoCPUX8664, machoCPUARM64)[:20], "darwin", "arm64", false},
		{"macho universal, slice missing", fatBinary(false, machoCPUARM64)[:4096], "darwin", "arm64", false},
		{"java class file", javaClass, "darwin", "arm64", false},
		{"macho on linux", machoHeader(machoCPUARM64, machoTypeExecute), "linux", "arm64", false},
		// Not executables at all
		{"empty", nil, "linux", "amd64", false},
		{"shell script", []byte("#!/bin/sh\necho dranzo-agent 9.9.9 (linux)\n"), "linux", "amd64", false},
		{"text", bytes.Repeat([]byte("hello "), 100), "windows", "amd64", false},
		{"zip", append([]byte("PK\x03\x04"), make([]byte, 100)...), "darwin", "arm64", false},
	}
	for _, c := range cases {
		err := CheckExecutable(bytes.NewReader(c.data), c.goos, c.goarch)
		if c.ok && err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
		if !c.ok {
			if err == nil {
				t.Errorf("%s: accepted", c.name)
			} else if !errors.Is(err, ErrNotExecutable) {
				t.Errorf("%s: error %v is not ErrNotExecutable", c.name, err)
			}
		}
	}
	if err := CheckExecutable(bytes.NewReader(nil), "plan9", "amd64"); err == nil || errors.Is(err, ErrNotExecutable) {
		t.Errorf("unsupported OS: %v", err)
	}
	if err := CheckExecutable(bytes.NewReader(nil), "linux", "riscv64"); err == nil || errors.Is(err, ErrNotExecutable) {
		t.Errorf("unsupported architecture: %v", err)
	}
}

// The test binary itself is a real executable of the platform under test.
func TestCheckExecutableFileOnRealBinary(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	if err := CheckExecutableFile(self, runtime.GOOS, runtime.GOARCH); err != nil {
		t.Fatalf("own test binary refused: %v", err)
	}
	other := "arm64"
	if runtime.GOARCH == "arm64" {
		other = "amd64"
	}
	if err := CheckExecutableFile(self, runtime.GOOS, other); !errors.Is(err, ErrNotExecutable) {
		t.Fatalf("own test binary accepted as %s: %v", other, err)
	}
	dir := t.TempDir()
	if err := CheckExecutableFile(dir, runtime.GOOS, runtime.GOARCH); !errors.Is(err, ErrNotExecutable) {
		t.Fatalf("a directory was accepted: %v", err)
	}
	if err := CheckExecutableFile(filepath.Join(dir, "missing"), runtime.GOOS, runtime.GOARCH); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
}
