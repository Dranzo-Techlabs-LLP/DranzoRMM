//go:build darwin

package session

import "golang.org/x/sys/unix"

// processTable reads pid, parent pid and session id of every process.
func processTable() []procInfo {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil
	}
	table := make([]procInfo, 0, len(procs))
	for i := range procs {
		pid := int(procs[i].Proc.P_pid)
		if pid <= 0 {
			continue
		}
		sid, err := unix.Getsid(pid)
		if err != nil {
			sid = -1
		}
		table = append(table, procInfo{pid: pid, ppid: int(procs[i].Eproc.Ppid), sid: sid})
	}
	return table
}
