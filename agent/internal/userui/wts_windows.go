//go:build windows

package userui

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modwtsapi32        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSSendMessage = modwtsapi32.NewProc("WTSSendMessageW")
)

// wtsMessageBox shows message boxes with WTSSendMessageW.
type wtsMessageBox struct{}

// Send implements messageBoxer.
func (wtsMessageBox) Send(sessionID uint32, title, text string, style, timeoutSeconds uint32, wait bool) (uint32, error) {
	t, err := windows.UTF16FromString(title)
	if err != nil {
		return 0, err
	}
	m, err := windows.UTF16FromString(text)
	if err != nil {
		return 0, err
	}
	if len(t) < 2 {
		t = []uint16{' ', 0}
	}
	if len(m) < 2 {
		m = []uint16{' ', 0}
	}
	if err := procWTSSendMessage.Find(); err != nil {
		return 0, err
	}
	var response uint32
	var bWait uintptr
	if wait {
		bWait = 1
	}
	// BOOL WTSSendMessageW(HANDLE hServer, DWORD SessionId, LPWSTR pTitle,
	//   DWORD TitleLength, LPWSTR pMessage, DWORD MessageLength, DWORD Style,
	//   DWORD Timeout, DWORD *pResponse, BOOL bWait);
	// Lengths are in bytes, without the terminating NUL.
	r, _, callErr := procWTSSendMessage.Call(
		0, // WTS_CURRENT_SERVER_HANDLE
		uintptr(sessionID),
		uintptr(unsafe.Pointer(&t[0])), //nolint:gosec // G103: Win32 interop
		uintptr((len(t)-1)*2),
		uintptr(unsafe.Pointer(&m[0])), //nolint:gosec // G103: Win32 interop
		uintptr((len(m)-1)*2),
		uintptr(style),
		uintptr(timeoutSeconds),
		uintptr(unsafe.Pointer(&response)), //nolint:gosec // G103: Win32 interop
		bWait,
	)
	if r == 0 {
		if callErr != nil && !errors.Is(callErr, windows.ERROR_SUCCESS) {
			return 0, callErr
		}
		return 0, errors.New("WTSSendMessageW failed")
	}
	return response, nil
}
