//go:build darwin

package config

func defaultPaths() Paths {
	const dir = "/Library/Application Support/DranzoRMM"
	return Paths{StateDir: dir, ConfigDir: dir}
}
