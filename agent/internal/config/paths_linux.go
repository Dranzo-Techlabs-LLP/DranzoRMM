//go:build linux

package config

func defaultPaths() Paths {
	return Paths{StateDir: "/var/lib/dranzormm", ConfigDir: "/etc/dranzormm"}
}
