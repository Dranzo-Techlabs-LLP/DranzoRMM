//go:build linux

package session

import (
	"os"
	"strconv"
	"strings"
)

// processTable reads pid, parent pid and session id of every process from /proc.
func processTable() []procInfo {
	dir, err := os.Open("/proc")
	if err != nil {
		return nil
	}
	defer func() { _ = dir.Close() }()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil
	}
	table := make([]procInfo, 0, len(names))
	for _, name := range names {
		pid, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		data, err := os.ReadFile("/proc/" + name + "/stat")
		if err != nil {
			continue
		}
		if p, ok := parseProcStat(pid, string(data)); ok {
			table = append(table, p)
		}
	}
	return table
}

// parseProcStat parses "pid (comm) state ppid pgrp session ...". The command
// name may contain spaces and parentheses, so fields are counted from the
// last ')'.
func parseProcStat(pid int, stat string) (procInfo, bool) {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return procInfo{}, false
	}
	f := strings.Fields(stat[i+1:])
	if len(f) < 4 {
		return procInfo{}, false
	}
	ppid, err1 := strconv.Atoi(f[1])
	sid, err2 := strconv.Atoi(f[3])
	if err1 != nil || err2 != nil {
		return procInfo{}, false
	}
	return procInfo{pid: pid, ppid: ppid, sid: sid}, true
}
