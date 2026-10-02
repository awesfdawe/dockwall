package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

type Policy struct {
	Network string `yaml:"network"`
	Rules   []Rule `yaml:"rules"`
}

type Config struct {
	Debounce     time.Duration `yaml:"debounce"`
	PollInterval time.Duration `yaml:"poll_interval"`
	Policies     []Policy      `yaml:"policies"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	cfg := &Config{
		Debounce:     500 * time.Millisecond,
		PollInterval: time.Minute,
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.Debounce <= 0 {
		c.Debounce = 500 * time.Millisecond
	}
	if c.PollInterval <= 0 {
		c.PollInterval = time.Minute
	}
	if len(c.Policies) == 0 {
		return errors.New("at least one policy must be defined")
	}

	for i, p := range c.Policies {
		if p.Network == "" {
			return fmt.Errorf("policy[%d]: network name is required", i)
		}
		if len(p.Rules) == 0 {
			return fmt.Errorf("policy[%d]: network %q has no rules", i, p.Network)
		}
		for j, r := range p.Rules {
			if r.From == "" || r.To == "" {
				return fmt.Errorf("policy[%d].rule[%d]: from and to must not be empty", i, j)
			}
			if r.From == "*" && r.To == "*" {
				return fmt.Errorf("policy[%d].rule[%d]: from and to cannot both be wildcard", i, j)
			}
		}
	}
	return nil
}
