package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type Capability string

const (
	CapRead    Capability = "read"
	CapWrite   Capability = "write"
	CapDelete  Capability = "delete"
	CapList    Capability = "list"
	CapEncrypt Capability = "encrypt"
	CapDecrypt Capability = "decrypt"
)

type Rule struct {
	Path         string       `yaml:"path"`
	Capabilities []Capability `yaml:"capabilities"`
	Deny         bool         `yaml:"deny"`
}

type Policy struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Rules       []Rule `yaml:"rules"`
}

// builtins are always available and can be overridden by a same-named YAML file.
var builtins = map[string]*Policy{
	"readonly": {
		Name:        "readonly",
		Description: "Read and list all KV secrets",
		Rules: []Rule{
			{Path: "secrets/kv/*", Capabilities: []Capability{CapRead, CapList}},
		},
	},
	"readwrite": {
		Name:        "readwrite",
		Description: "Full access to KV secrets and transit encrypt/decrypt",
		Rules: []Rule{
			{Path: "secrets/kv/*", Capabilities: []Capability{CapRead, CapWrite, CapDelete, CapList}},
			{Path: "secrets/transit/*", Capabilities: []Capability{CapEncrypt, CapDecrypt}},
		},
	},
	"admin": {
		Name:        "admin",
		Description: "Full access to all secret engines",
		Rules: []Rule{
			{Path: "secrets/kv/*", Capabilities: []Capability{CapRead, CapWrite, CapDelete, CapList}},
			{Path: "secrets/transit/*", Capabilities: []Capability{CapEncrypt, CapDecrypt}},
			{Path: "secrets/db/*", Capabilities: []Capability{CapRead, CapWrite, CapDelete, CapList}},
		},
	},
}

type Engine struct {
	mu       sync.RWMutex
	policies map[string]*Policy
	dir      string
}

func NewEngine(dir string) *Engine {
	return &Engine{
		policies: make(map[string]*Policy),
		dir:      dir,
	}
}

// Builtins returns the names of built-in policies.
func Builtins() []string {
	return []string{"readonly", "readwrite", "admin"}
}

// LoadAll reads all YAML policy files from the configured directory.
func (e *Engine) LoadAll() error {
	entries, err := os.ReadDir(e.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read policy dir %s: %w", e.dir, err)
	}

	loaded := make(map[string]*Policy)
	for _, entry := range entries {
		if entry.IsDir() || !isYAML(entry.Name()) {
			continue
		}
		p, err := loadFile(filepath.Join(e.dir, entry.Name()))
		if err != nil {
			return fmt.Errorf("load policy %s: %w", entry.Name(), err)
		}
		loaded[p.Name] = p
	}

	e.mu.Lock()
	e.policies = loaded
	e.mu.Unlock()
	return nil
}

// LoadPolicy loads or replaces a single named policy from a YAML file.
func (e *Engine) LoadPolicy(path string) error {
	p, err := loadFile(path)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.policies[p.Name] = p
	e.mu.Unlock()
	return nil
}

// SetPolicy registers an in-memory policy (used in tests and enrollment).
func (e *Engine) SetPolicy(p *Policy) {
	e.mu.Lock()
	e.policies[p.Name] = p
	e.mu.Unlock()
}

// Get returns the named policy.
func (e *Engine) Get(name string) (*Policy, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p, ok := e.policies[name]
	return p, ok
}

// Allowed returns true if the named policy grants the capability on the given path.
// Explicit deny rules override allows. Default is deny.
// The special policy name "root" grants all capabilities (used in dev mode).
func (e *Engine) Allowed(policyName, path string, cap Capability) bool {
	if policyName == "root" {
		return true
	}
	e.mu.RLock()
	p, ok := e.policies[policyName]
	e.mu.RUnlock()
	if !ok {
		p, ok = builtins[policyName]
		if !ok {
			return false
		}
	}

	allowed := false
	for _, rule := range p.Rules {
		if !matchPath(rule.Path, path) {
			continue
		}
		if rule.Deny {
			return false // explicit deny wins immediately
		}
		if hasCapability(rule.Capabilities, cap) {
			allowed = true
		}
	}
	return allowed
}

func loadFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.Name == "" {
		return nil, fmt.Errorf("policy file %s missing name field", path)
	}
	return &p, nil
}

// matchPath supports a single trailing wildcard: "secrets/kv/prod/*"
func matchPath(pattern, path string) bool {
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	}
	return pattern == path
}

func hasCapability(caps []Capability, target Capability) bool {
	for _, c := range caps {
		if c == target {
			return true
		}
	}
	return false
}

func isYAML(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}
