package syscheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckPaths_Success(t *testing.T) {
	dir := t.TempDir()
	procPath := filepath.Join(dir, "bridge-nf-call-iptables")
	modulePath := filepath.Join(dir, "br_netfilter")

	if err := os.Mkdir(modulePath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(procPath, []byte("1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := checkPaths(procPath, modulePath); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestCheckPaths_ModuleMissing(t *testing.T) {
	dir := t.TempDir()
	procPath := filepath.Join(dir, "bridge-nf-call-iptables")
	modulePath := filepath.Join(dir, "br_netfilter")

	err := checkPaths(procPath, modulePath)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCheckPaths_ValueZero(t *testing.T) {
	dir := t.TempDir()
	procPath := filepath.Join(dir, "bridge-nf-call-iptables")
	modulePath := filepath.Join(dir, "br_netfilter")

	if err := os.Mkdir(modulePath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(procPath, []byte("0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	err := checkPaths(procPath, modulePath)
	if err == nil {
		t.Fatal("expected error when value is 0, got nil")
	}
}
