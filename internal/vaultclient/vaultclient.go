package vaultclient

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/hashicorp/vault/api"
)

var (
	Client *VaultClient
)

// VaultClient is a single self-contained vault client
type VaultClient struct {
	VaultAddr  string      `yaml:"vaultAddr"`
	CIDR       string      `yaml:"cidr"`
	AuthMethod string      `yaml:"authMethod"`
	Role       string      `yaml:"role"`
	Path       string      `yaml:"path"`
	KubeToken  string      // auto-filled
	Client     *api.Client // auto-filled
	Token      string      // auto-filled
}

// NewClients creates and returns a new vault client with a valid token or error
func (vc *VaultClient) NewClient() (*api.Client, error) {
	l := log.WithFields(log.Fields{
		"vaultAddr": vc.VaultAddr,
		"action":    "vault.NewClient",
	})
	l.Printf("vault.NewClient")
	config := &api.Config{
		Address: vc.VaultAddr,
	}
	var err error
	vc.Client, err = api.NewClient(config)
	if err != nil {
		l.Printf("vault.NewClient error: %v\n", err)
		return vc.Client, err
	}
	if os.Getenv("KUBE_TOKEN") != "" {
		l.Printf("vault.NewClient using KUBE_TOKEN")
		fd, err := ioutil.ReadFile(os.Getenv("KUBE_TOKEN"))
		if err != nil {
			l.Printf("vault.NewClient error: %v\n", err)
			return vc.Client, err
		}
		vc.KubeToken = string(fd)
	}
	_, terr := vc.NewToken()
	if terr != nil {
		l.Printf("vault.NewClient error: %v\n", terr)
		return vc.Client, terr
	}
	Client = vc
	return vc.Client, err
}

// Login creates a vault token with the k8s auth provider
func (vc *VaultClient) Login() (string, error) {
	l := log.WithFields(log.Fields{
		"vaultAddr":  vc.VaultAddr,
		"action":     "vault.Login",
		"role":       vc.Role,
		"authMethod": vc.AuthMethod,
	})
	l.Printf("vault.Login")
	options := map[string]interface{}{
		"role": vc.Role,
		"jwt":  vc.KubeToken,
	}
	path := fmt.Sprintf("auth/%s/login", vc.AuthMethod)
	secret, err := vc.Client.Logical().Write(path, options)
	if err != nil {
		l.Printf("vault.Login(%s) error: %v\n", vc.AuthMethod, err)
		return "", err
	}
	vc.Token = secret.Auth.ClientToken
	l.Printf("vault.Login(%s) success\n", vc.AuthMethod)
	vc.Client.SetToken(vc.Token)
	return vc.Token, nil
}

// NewToken generate a new token for session. If LOCAL env var is set and the token is as well, the login is
// skipped and the token is used instead.
func (vc *VaultClient) NewToken() (string, error) {
	l := log.WithFields(log.Fields{
		"vaultAddr": vc.VaultAddr,
		"action":    "vault.NewToken",
	})
	l.Printf("vault.NewToken")
	if os.Getenv("LOCAL") != "" && vc.Token != "" {
		l.Printf("vault.NewToken using local token")
		vc.Client.SetToken(vc.Token)
		return vc.Token, nil
	}
	l.Printf("vault.NewToken calling Login")
	return vc.Login()
}

// GetKVSecret retrieves a kv secret from vault
func (vc *VaultClient) GetKVSecret(s string) (map[string]interface{}, error) {
	l := log.WithFields(log.Fields{
		"vaultAddr": vc.VaultAddr,
		"action":    "vault.GetKVSecret",
	})
	l.Printf("vault.GetKVSecret")
	var secrets map[string]interface{}
	if s == "" {
		l.Printf("vault.GetKVSecret error: secret path is empty")
		return secrets, errors.New("secret path required")
	}
	s = "devops/data/stratus-dev/" + s
	secret, err := vc.Client.Logical().Read(s)
	if err != nil {
		l.Printf("vault.GetKVSecret(%s) c.Read error: %v\n", s, err)
		return secrets, err
	}
	if secret == nil || secret.Data == nil {
		l.Printf("vault.GetKVSecret(%s) error: secret is nil\n", s)
		return nil, errors.New("secret not found")
	}
	l.Printf("vault.GetKVSecret(%s) success\n", s)
	return secret.Data["data"].(map[string]interface{}), nil
}

// GetKVSecretRetry will login and retry secret access on failure
// to gracefully handle token expiration
func (vc *VaultClient) GetKVSecretRetry(s string) (map[string]interface{}, error) {
	l := log.WithFields(log.Fields{
		"vaultAddr": vc.VaultAddr,
		"action":    "vault.GetKVSecretRetry",
	})
	l.Printf("vault.GetKVSecretRetry")
	var sec map[string]interface{}
	var err error
	sec, err = vc.GetKVSecret(s)
	if err != nil {
		l.Printf("vault.GetKVSecretRetry(%s) error: %v\n", s, err)
		_, terr := vc.NewToken()
		if terr != nil {
			l.Printf("vault.GetKVSecretRetry(%s) error: %v\n", s, terr)
			return sec, terr
		}
		sec, err = vc.GetKVSecret(s)
		if err != nil {
			l.Printf("vault.GetKVSecretRetry(%s) error: %v\n", s, err)
			return sec, err
		}
	}
	l.Printf("vault.GetKVSecretRetry(%s) success\n", s)
	return sec, err
}
