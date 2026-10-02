package firewall

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

type mockRunner struct {
	chains map[string][]string
	rules  map[string][][]string
}

func newMockRunner() *mockRunner {
	return &mockRunner{
		chains: map[string][]string{
			TableFilter: {ChainDockerUser},
		},
		rules: map[string][][]string{
			ChainDockerUser: {},
			ChainDockwall:   {},
		},
	}
}

func (m *mockRunner) ClearChain(table, chain string) error {
	m.rules[chain] = [][]string{}
	return nil
}

func (m *mockRunner) ClearAndDeleteChain(table, chain string) error {
	delete(m.rules, chain)
	chains := m.chains[table]
	var updated []string
	for _, c := range chains {
		if c != chain {
			updated = append(updated, c)
		}
	}
	m.chains[table] = updated
	return nil
}

func (m *mockRunner) ChainExists(table, chain string) (bool, error) {
	if slices.Contains(m.chains[table], chain) {
		return true, nil
	}
	return false, nil
}

func (m *mockRunner) NewChain(table, chain string) error {
	m.chains[table] = append(m.chains[table], chain)
	m.rules[chain] = [][]string{}
	return nil
}

func (m *mockRunner) Exists(table, chain string, rulespec ...string) (bool, error) {
	rules := m.rules[chain]
	for _, r := range rules {
		if reflect.DeepEqual(r, rulespec) {
			return true, nil
		}
	}
	return false, nil
}

func (m *mockRunner) Insert(table, chain string, pos int, rulespec ...string) error {
	rules := m.rules[chain]
	if pos == 1 {
		m.rules[chain] = append([][]string{rulespec}, rules...)
	} else {
		m.rules[chain] = append(rules, rulespec)
	}
	return nil
}

func (m *mockRunner) Append(table, chain string, rulespec ...string) error {
	m.rules[chain] = append(m.rules[chain], rulespec)
	return nil
}

func (m *mockRunner) DeleteIfExists(table, chain string, rulespec ...string) error {
	rules := m.rules[chain]
	var updated [][]string
	for _, r := range rules {
		if !reflect.DeepEqual(r, rulespec) {
			updated = append(updated, r)
		}
	}
	m.rules[chain] = updated
	return nil
}

func TestManager_Init(t *testing.T) {
	runner := newMockRunner()
	mgr := NewWithRunner(runner)

	if err := mgr.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	exists, _ := runner.ChainExists(TableFilter, ChainDockwall)
	if !exists {
		t.Errorf("expected chain %s to exist", ChainDockwall)
	}

	jumpExists, _ := runner.Exists(TableFilter, ChainDockerUser, "-j", ChainDockwall)
	if !jumpExists {
		t.Errorf("expected jump to %s in %s", ChainDockwall, ChainDockerUser)
	}
}

func TestManager_Sync(t *testing.T) {
	runner := newMockRunner()
	mgr := NewWithRunner(runner)

	policies := []NetworkPolicy{
		{
			BridgeName: "br-proxy123",
			Rules: []RuleTarget{
				{FromIP: "172.20.0.2", ToIP: ""},
			},
		},
		{
			BridgeName: "br-bypass456",
			Rules: []RuleTarget{
				{FromIP: "", ToIP: "172.21.0.2"},
			},
		},
	}

	if err := mgr.Sync(policies); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	rules := runner.rules[ChainDockwall]
	if len(rules) == 0 {
		t.Fatal("expected rules in DOCKWALL, got none")
	}

	var flatRules []string
	for _, r := range rules {
		flatRules = append(flatRules, strings.Join(r, " "))
	}

	expectedPrefixes := []string{
		"-i br-proxy123 -o br-proxy123 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"-i br-proxy123 -o br-proxy123 -s 172.20.0.2 -m conntrack --ctstate NEW -j ACCEPT",
		"-i br-proxy123 -o br-proxy123 -j DROP",
		"-i br-bypass456 -o br-bypass456 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"-i br-bypass456 -o br-bypass456 -d 172.21.0.2 -m conntrack --ctstate NEW -j ACCEPT",
		"-i br-bypass456 -o br-bypass456 -j DROP",
		"-j RETURN",
	}

	if len(flatRules) != len(expectedPrefixes) {
		t.Fatalf("expected %d rules, got %d:\n%s", len(expectedPrefixes), len(flatRules), strings.Join(flatRules, "\n"))
	}

	for i, expected := range expectedPrefixes {
		if flatRules[i] != expected {
			t.Errorf("rule[%d] mismatch:\nwant: %s\ngot:  %s", i, expected, flatRules[i])
		}
	}
}

func TestManager_Cleanup(t *testing.T) {
	runner := newMockRunner()
	mgr := NewWithRunner(runner)

	if err := mgr.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	jumpExists, _ := runner.Exists(TableFilter, ChainDockerUser, "-j", ChainDockwall)
	if jumpExists {
		t.Errorf("expected jump to %s to be deleted", ChainDockwall)
	}

	chainExists, _ := runner.ChainExists(TableFilter, ChainDockwall)
	if chainExists {
		t.Errorf("expected chain %s to be deleted", ChainDockwall)
	}
}
