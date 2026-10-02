package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_Valid(t *testing.T) {
	yamlContent := `
debounce: 250ms
poll_interval: 30s
policies:
  - network: proxy
    rules:
      - from: reverse-proxy
        to: "*"
  - network: bypass
    rules:
      - from: "*"
        to: xray-core
`
	tmp := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tmp, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Debounce != 250*time.Millisecond {
		t.Errorf("expected debounce 250ms, got %v", cfg.Debounce)
	}
	if cfg.PollInterval != 30*time.Second {
		t.Errorf("expected poll_interval 30s, got %v", cfg.PollInterval)
	}
	if len(cfg.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(cfg.Policies))
	}
	if cfg.Policies[0].Network != "proxy" {
		t.Errorf("expected network 'proxy', got %s", cfg.Policies[0].Network)
	}
	if cfg.Policies[0].Rules[0].From != "reverse-proxy" || cfg.Policies[0].Rules[0].To != "*" {
		t.Errorf("unexpected rule in policy 0: %+v", cfg.Policies[0].Rules[0])
	}
}

func TestLoad_Defaults(t *testing.T) {
	yamlContent := `
policies:
  - network: test-net
    rules:
      - from: "*"
        to: app
`
	tmp := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tmp, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Debounce != 500*time.Millisecond {
		t.Errorf("expected default debounce 500ms, got %v", cfg.Debounce)
	}
	if cfg.PollInterval != time.Minute {
		t.Errorf("expected default poll_interval 1m, got %v", cfg.PollInterval)
	}
}

func TestLoad_Invalid(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{
			name:    "empty policies",
			content: "debounce: 1s\n",
		},
		{
			name: "empty network name",
			content: `
policies:
  - network: ""
    rules:
      - from: app
        to: "*"
`,
		},
		{
			name: "both wildcards",
			content: `
policies:
  - network: proxy
    rules:
      - from: "*"
        to: "*"
`,
		},
		{
			name: "empty from or to",
			content: `
policies:
  - network: proxy
    rules:
      - from: ""
        to: app
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(tmp, []byte(tc.content), 0644); err != nil {
				t.Fatal(err)
			}
			_, err := Load(tmp)
			if err == nil {
				t.Fatalf("expected error for case %q, got nil", tc.name)
			}
		})
	}
}
