package firewall

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"
)

const (
	TableFilter     = "filter"
	ChainDockerUser = "DOCKER-USER"
	ChainDockwall   = "DOCKWALL"
	TargetAccept    = "ACCEPT"
	TargetDrop      = "DROP"
	TargetReturn    = "RETURN"
)

type RuleTarget struct {
	FromIP string
	ToIP   string
}

type NetworkPolicy struct {
	BridgeName string
	Rules      []RuleTarget
}

type Runner interface {
	ClearChain(table, chain string) error
	ClearAndDeleteChain(table, chain string) error
	ChainExists(table, chain string) (bool, error)
	NewChain(table, chain string) error
	Exists(table, chain string, rulespec ...string) (bool, error)
	Insert(table, chain string, pos int, rulespec ...string) error
	Append(table, chain string, rulespec ...string) error
	DeleteIfExists(table, chain string, rulespec ...string) error
}

type Manager struct {
	runner Runner
}

func New() (*Manager, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("initializing iptables: %w", err)
	}
	return &Manager{runner: ipt}, nil
}

func NewWithRunner(runner Runner) *Manager {
	return &Manager{runner: runner}
}

func (m *Manager) Init() error {
	exists, err := m.runner.ChainExists(TableFilter, ChainDockerUser)
	if err != nil {
		return fmt.Errorf("checking %s chain: %w", ChainDockerUser, err)
	}
	if !exists {
		if err := m.runner.NewChain(TableFilter, ChainDockerUser); err != nil {
			return fmt.Errorf("creating %s chain: %w", ChainDockerUser, err)
		}
	}

	exists, err = m.runner.ChainExists(TableFilter, ChainDockwall)
	if err != nil {
		return fmt.Errorf("checking %s chain: %w", ChainDockwall, err)
	}
	if !exists {
		if err := m.runner.NewChain(TableFilter, ChainDockwall); err != nil {
			return fmt.Errorf("creating %s chain: %w", ChainDockwall, err)
		}
	}

	jumpExists, err := m.runner.Exists(TableFilter, ChainDockerUser, "-j", ChainDockwall)
	if err != nil {
		return fmt.Errorf("checking jump rule in %s: %w", ChainDockerUser, err)
	}
	if !jumpExists {
		if err := m.runner.Insert(TableFilter, ChainDockerUser, 1, "-j", ChainDockwall); err != nil {
			return fmt.Errorf("inserting jump rule in %s: %w", ChainDockerUser, err)
		}
	}

	return nil
}

func (m *Manager) Sync(policies []NetworkPolicy) error {
	if err := m.Init(); err != nil {
		return err
	}

	if err := m.runner.ClearChain(TableFilter, ChainDockwall); err != nil {
		return fmt.Errorf("clearing %s: %w", ChainDockwall, err)
	}

	for _, p := range policies {
		if p.BridgeName == "" {
			continue
		}

		if err := m.runner.Append(TableFilter, ChainDockwall,
			"-i", p.BridgeName, "-o", p.BridgeName,
			"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
			"-j", TargetAccept,
		); err != nil {
			return fmt.Errorf("adding conntrack rule for %s: %w", p.BridgeName, err)
		}

		for _, r := range p.Rules {
			var ruleSpec []string

			switch {
			case r.FromIP != "" && r.ToIP == "":
				ruleSpec = []string{
					"-i", p.BridgeName, "-o", p.BridgeName,
					"-s", r.FromIP,
					"-m", "conntrack", "--ctstate", "NEW",
					"-j", TargetAccept,
				}
			case r.FromIP == "" && r.ToIP != "":
				ruleSpec = []string{
					"-i", p.BridgeName, "-o", p.BridgeName,
					"-d", r.ToIP,
					"-m", "conntrack", "--ctstate", "NEW",
					"-j", TargetAccept,
				}
			case r.FromIP != "" && r.ToIP != "":
				ruleSpec = []string{
					"-i", p.BridgeName, "-o", p.BridgeName,
					"-s", r.FromIP, "-d", r.ToIP,
					"-m", "conntrack", "--ctstate", "NEW",
					"-j", TargetAccept,
				}
			default:
				continue
			}

			if err := m.runner.Append(TableFilter, ChainDockwall, ruleSpec...); err != nil {
				return fmt.Errorf("adding rule for bridge %s: %w", p.BridgeName, err)
			}
		}

		if err := m.runner.Append(TableFilter, ChainDockwall,
			"-i", p.BridgeName, "-o", p.BridgeName,
			"-j", TargetDrop,
		); err != nil {
			return fmt.Errorf("adding drop rule for %s: %w", p.BridgeName, err)
		}
	}

	if err := m.runner.Append(TableFilter, ChainDockwall, "-j", TargetReturn); err != nil {
		return fmt.Errorf("adding return rule: %w", err)
	}

	return nil
}

func (m *Manager) Cleanup() error {
	if err := m.runner.DeleteIfExists(TableFilter, ChainDockerUser, "-j", ChainDockwall); err != nil {
		return fmt.Errorf("deleting jump rule: %w", err)
	}
	if err := m.runner.ClearAndDeleteChain(TableFilter, ChainDockwall); err != nil {
		return fmt.Errorf("deleting %s chain: %w", ChainDockwall, err)
	}
	return nil
}
