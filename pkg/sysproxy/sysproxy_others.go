//go:build !linux && !windows && !android
// +build !linux,!windows,!android

package sysproxy

func SetSysProxy(_, _ string) {}
func UnsetSysProxy()          {}
