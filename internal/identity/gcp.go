package identity

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"

	"github.com/robertlestak/stratus/internal/vaultclient"
	log "github.com/sirupsen/logrus"
)

// GCPCredentials is the structure of the GCP ServiceAccount credentials
type GCPCredentials struct {
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	AuthURI                 string `json:"auth_uri"`
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id"`
	ClientX509CertURL       string `json:"client_x509_cert_url"`
	PrivateKey              string `json:"private_key"`
	PrivateKeyID            string `json:"private_key_id"`
	ProjectID               string `json:"project_id"`
	TokenURI                string `json:"token_uri"`
	Type                    string `json:"type"`
}

// GetGCPSAFromVault returns the GCP ServiceAccount credentials from Vault
func (id *Identity) GetGCPSAFromVault(vaultClient *vaultclient.VaultClient) (map[string]interface{}, error) {
	l := log.WithFields(log.Fields{
		"func":      "GetGCPSAFromVault",
		"requestId": id.RequestID,
	})
	l.Info("GetGCPSAFromVault")
	s, serr := vaultClient.GetKVSecretRetry(id.ID)
	if serr != nil {
		l.WithError(serr).Error("GetGCPSAFromVault failed")
		return s, serr
	}
	id.Credentials = s
	return id.Credentials, nil
}

// ValidGCP checks if the GCP ServiceAccount credentials are valid
func (id *Identity) ValidGCP() bool {
	l := log.WithFields(log.Fields{
		"func":      "ValidGCP",
		"requestId": id.RequestID,
	})
	l.Info("start")
	if id.Provider != "gcp" {
		l.Info("provider not gcp")
		return false
	}
	if id.Credentials == nil {
		l.Info("credentials nil")
		return false
	}
	c := &GCPCredentials{}
	var err error
	jd, jerr := json.Marshal(id.Credentials)
	if jerr != nil {
		l.WithError(jerr).Error("ValidGCP failed")
		return false
	}
	jerr = json.Unmarshal(jd, &c)
	if jerr != nil {
		l.WithError(jerr).Error("ValidGCP failed")
		return false
	}
	if c.ClientEmail == "" || c.ClientX509CertURL == "" {
		l.Error("client email and cert required")
		return false
	}
	// ensure that the specified identity ID is the same as the client email
	if id.ID != c.ClientEmail {
		l.WithField("id", id.ID).WithField("client_email", c.ClientEmail).Error("id does not match client email")
		return false
	}
	// validate the google cert + key
	if c.Validate() != nil {
		l.WithError(err).Error("validate failed")
		return false
	}
	return true
}

// getClientCert retrieves the public certificate for a GCP Service Account
func (c *GCPCredentials) getClientCert() (string, error) {
	l := log.WithFields(log.Fields{
		"func": "getClientCert",
	})
	l.Info("start")
	hc := &http.Client{}
	req, err := http.NewRequest("GET", c.ClientX509CertURL, nil)
	if err != nil {
		l.WithError(err).Error("getClientCert failed")
		return "", err
	}
	res, rerr := hc.Do(req)
	if rerr != nil {
		l.WithError(rerr).Error("getClientCert failed")
		return "", rerr
	}
	defer res.Body.Close()
	rd := map[string]string{}
	jerr := json.NewDecoder(res.Body).Decode(&rd)
	if jerr != nil {
		l.WithError(jerr).Error("getClientCert failed")
		return "", jerr
	}
	var rv string
	if r, ok := rd[c.PrivateKeyID]; ok {
		rv = r
	}
	return rv, nil
}

// Validate validates the GCP ServiceAccount credentials against the GCP Public Key
func (c *GCPCredentials) Validate() error {
	l := log.WithFields(log.Fields{
		"func": "GCPCredentials.Validate",
	})
	l.Info("start")
	// retrieve client cert
	cc, err := c.getClientCert()
	if err != nil {
		l.WithError(err).Error("GCPCredentials.Validate failed")
		return err
	}
	// load public cert and our private key
	cert, err := tls.X509KeyPair([]byte(cc), []byte(c.PrivateKey))
	if err != nil {
		l.WithError(err).Error("GCPCredentials.Validate failed")
		return err
	}
	// parse the loaded certificate
	_, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		l.WithError(err).Error("GCPCredentials.Validate failed")
		return err
	}
	// no errors, cert and key match
	return nil
}
