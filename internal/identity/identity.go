package identity

import (
	"errors"

	"github.com/robertlestak/stratus/internal/vaultclient"
	log "github.com/sirupsen/logrus"
)

// ProviderName contains supported providers
type ProviderName string

const (
	ProviderAWS ProviderName = "aws"
	ProviderGCP ProviderName = "gcp"
	ProviderAZR ProviderName = "azr"
	ProviderK8S ProviderName = "k8s"
)

// Identity contains a single identity
type Identity struct {
	ID          string                 `json:"id" yaml:"id"`
	Provider    ProviderName           `json:"provider" yaml:"provider"`
	Region      string                 `json:"region" yaml:"region"`
	Credentials map[string]interface{} `json:"credentials" yaml:"credentials"`
	RequestID   string                 `json:"request_id" yaml:"-"`
}

// IAMMap contains a single identity mapping and the corresponding request ID for audit log
type IAMMap struct {
	Source    Identity `json:"source" yaml:"source"`
	Target    Identity `json:"target" yaml:"target"`
	RequestID string   `json:"requestId"`
}

// Valid checks the identities validity with the given provider
func (id *Identity) Valid() bool {
	l := log.WithFields(log.Fields{
		"func": "Valid",
	})
	l.Printf("start")
	if id.Provider == "" {
		l.Printf("%+v", errors.New("provider not set"))
		return false
	}
	if id.Provider == ProviderAWS {
		return id.ValidAWS()
	} else if id.Provider == ProviderGCP {
		return id.ValidGCP()
	} else if id.Provider == ProviderK8S {
		return id.ValidK8S()
	}
	l.Errorf("%+v", "identity invalid")
	return false
}

// FindIDinMap returns the IAMMap for the given source identity
// this assumes validation has already been performed and the Source identity
// has the right to assume the Target identity
func (im *IAMMap) FindIDinMap(iamMap []IAMMap) (*IAMMap, error) {
	for _, iam := range iamMap {
		if im.Source.ID == iam.Source.ID && im.Target.ID == iam.Target.ID {
			log.Printf("found identity %+v", iam)
			return &iam, nil
		}
	}
	return nil, errors.New("identity not found")
}

// GetCredentials returns the target credentials for the given source identity
// this performs no vlaidation and assumes the source identity has the right to
// assume the target identity
func (im *IAMMap) GetCredentials(vc *vaultclient.VaultClient) (map[string]interface{}, error) {
	l := log.WithFields(log.Fields{
		"func":      "getCredentials",
		"requestId": im.RequestID,
	})
	l.Printf("start")
	if im.Target.Provider == ProviderGCP {
		return im.Target.GetGCPSAFromVault(vc)
	} else if im.Target.Provider == ProviderAWS {
		return im.Target.CreateAWSSession()
	} else if im.Target.Provider == ProviderK8S {
		return im.Target.GetK8SSSAFromVault(vc)
	}
	return nil, errors.New("provider not supported")
}
