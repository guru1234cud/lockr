package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server         ServerConfig         `yaml:"server"`
	Storage        StorageConfig        `yaml:"storage"`
	Audit          AuditConfig          `yaml:"audit"`
	Policy         PolicyConfig         `yaml:"policy"`
	Session SessionConfig `yaml:"session"`
	LogLevel       string               `yaml:"log_level"`
}

type ServerConfig struct {
	Addr    string `yaml:"addr"`
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	TLSCA   string `yaml:"tls_ca"`
}

type StorageConfig struct {
	DataDir       string `yaml:"data_dir"`
	MasterKeyPath string `yaml:"master_key_path"`
}

type AuditConfig struct {
	LogFile string `yaml:"log_file"`
}

type PolicyConfig struct {
	Dir string `yaml:"dir"`
}

type SessionConfig struct {
	TTL    time.Duration `yaml:"ttl"`
	MaxTTL time.Duration `yaml:"max_ttl"`
}

func Defaults() *Config {
	return &Config{
		Server: ServerConfig{
			Addr:    "0.0.0.0:8300",
			TLSCert: "/etc/lockr/tls/server.crt",
			TLSKey:  "/etc/lockr/tls/server.key",
			TLSCA:   "/etc/lockr/tls/ca.crt",
		},
		Storage: StorageConfig{
			DataDir:       "/var/lib/lockr/data",
			MasterKeyPath: "/var/lib/lockr/master.key.enc",
		},
		Audit: AuditConfig{
			LogFile: "/var/lib/lockr/audit.log",
		},
		Policy: PolicyConfig{
			Dir: "/etc/lockr/policies",
		},
		Session: SessionConfig{
			TTL:    1 * time.Hour,
			MaxTTL: 24 * time.Hour,
		},
		LogLevel: "info",
	}
}

func Load(path string) (*Config, error) {
	cfg := Defaults()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.Server.Addr == "" {
		return fmt.Errorf("server.addr is required")
	}
	if c.Storage.DataDir == "" {
		return fmt.Errorf("storage.data_dir is required")
	}
	if c.Storage.MasterKeyPath == "" {
		return fmt.Errorf("storage.master_key_path is required")
	}
	return nil
}
