//go:build windows

package agentcore_test

const (
	scriptLanguage = "cmd"
	markerScript   = "@echo off\r\necho out:%1\r\necho err-line 1>&2\r\necho ran>>\"%MARKER%\"\r\nexit /b 3\r\n"
	sleepScript    = "@echo off\r\nping -n 120 127.0.0.1 >NUL\r\n"
)
