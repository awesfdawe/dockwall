package syscheck

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	defaultProcPath   = "/proc/sys/net/bridge/bridge-nf-call-iptables"
	defaultModulePath = "/sys/module/br_netfilter"
)

func CheckBrNetfilter() error {
	return checkPaths(defaultProcPath, defaultModulePath)
}

func checkPaths(procPath, modulePath string) error {
	if _, err := os.Stat(modulePath); errors.Is(err, os.ErrNotExist) {
		if _, procErr := os.Stat(procPath); errors.Is(procErr, os.ErrNotExist) {
			return errors.New("br_netfilter kernel module is not loaded")
		}
	}

	data, err := os.ReadFile(procPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", procPath, err)
	}

	val := strings.TrimSpace(string(data))
	if val != "1" {
		return fmt.Errorf("bridge-nf-call-iptables is %q, expected \"1\"", val)
	}

	return nil
}
