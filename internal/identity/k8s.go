package identity

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/mitchellh/mapstructure"
	"github.com/robertlestak/stratus/internal/vaultclient"
	log "github.com/sirupsen/logrus"
	"k8s.io/api/authentication/v1beta1"
)

// K8SIdentity is the identity for a k8s cluster
type K8SIdentity struct {
	ClusterName     string `json:"clusterName"`
	Namespace       string `json:"namespace"`
	SA              string `json:"sa"`
	JWT             string `json:"jwt"`
	ClusterHost     string `json:"clusterHost"`
	ClusterCA       string `json:"clusterCA"`
	ValidationToken string `json:"validationToken"`
}

// GetValidation retrieves the validateion SA token from vault
func (k *K8SIdentity) GetValidation(cluster string, vaultClient *vaultclient.VaultClient) error {
	l := log.WithFields(log.Fields{
		"cluster": cluster,
	})
	l.Info("GetValidationToken")
	s, serr := vaultClient.GetKVSecretRetry(k.ClusterName + "/validation")
	if serr != nil {
		l.WithError(serr).Error("GetGCPSAFromVault failed")
		return serr
	}
	err := mapstructure.Decode(s, &k)
	if err != nil {
		l.WithError(err).Error("Failed to decode secret")
		return err
	}
	return nil
}

// Validate validates the k8s identity against the k8s api
func (k *K8SIdentity) Validate() (*v1beta1.TokenReview, error) {
	l := log.WithFields(log.Fields{
		"cluster":   k.ClusterName,
		"namespace": k.Namespace,
		"sa":        k.SA,
	})
	l.Info("Validate")
	trr := &v1beta1.TokenReview{}
	gerr := k.GetValidation(k.ClusterName, vaultclient.Client)
	if gerr != nil {
		l.WithError(gerr).Error("GetValidationToken failed")
		return trr, gerr
	}
	caCertPool := x509.NewCertPool()
	sDec, berr := base64.StdEncoding.DecodeString(k.ClusterCA)
	if berr != nil {
		l.Error(berr)
		return trr, berr
	}
	caCertPool.AppendCertsFromPEM(sDec)
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}
	tr := &v1beta1.TokenReview{
		Spec: v1beta1.TokenReviewSpec{
			Token: k.JWT,
		},
	}
	b, err := json.Marshal(tr)
	if err != nil {
		l.Error(err)
		return trr, err
	}
	req, err := http.NewRequest("POST", k.ClusterHost+"/apis/authentication.k8s.io/v1beta1/tokenreviews", bytes.NewBuffer(b))
	if err != nil {
		l.Error(err)
		return trr, err
	}
	tDec, berr := base64.StdEncoding.DecodeString(k.ValidationToken)
	if berr != nil {
		l.Error(berr)
		return trr, berr
	}
	req.Header.Add("Authorization", "Bearer "+string(tDec))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		l.Error(err)
		return trr, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(trr)
	if err != nil {
		l.Error(err)
		return trr, err
	}
	if !trr.Status.Authenticated {
		l.Error("Token not authenticated")
		return trr, errors.New("token not authenticated")
	}
	return trr, nil
}

// ValidK8S extends the Identity to validate a k8s identity
func (id *Identity) ValidK8S() bool {
	l := log.WithFields(log.Fields{
		"action": "ValidK8S",
	})
	l.Info("ValidK8S")
	if id.Provider != "k8s" {
		return false
	}
	var k8screds struct {
		ClusterName string `json:"clusterName"`
		Namespace   string `json:"namespace"`
		SA          string `json:"sa"`
		JWT         string `json:"jwt"`
	}
	err := mapstructure.Decode(id.Credentials, &k8screds)
	if err != nil {
		l.WithError(err).Error("Failed to decode credentials")
		return false
	}
	if k8screds.JWT == "" {
		l.Error("JWT is empty")
		return false
	}
	k := &K8SIdentity{
		ClusterName: k8screds.ClusterName,
		Namespace:   k8screds.Namespace,
		SA:          k8screds.SA,
		JWT:         k8screds.JWT,
	}
	tr, err := k.Validate()
	if err != nil {
		l.WithError(err).Error("Validate failed")
		return false
	}
	if tr.Status.User.Username != id.ID {
		l.Error("Username does not match")
		return false
	}
	return true
}

// GetK8SSSAFromVault retrieves the configured k8s SSA from vault
func (id *Identity) GetK8SSSAFromVault(vaultClient *vaultclient.VaultClient) (map[string]interface{}, error) {
	l := log.WithFields(log.Fields{
		"action": "GetK8SSSAFromVault",
	})
	l.Info("GetK8SSSAFromVault")

	var k8screds struct {
		ClusterName string `json:"clusterName"`
		JWT         string `json:"jwt"`
	}
	err := mapstructure.Decode(id.Credentials, &k8screds)
	if err != nil {
		l.WithError(err).Error("Failed to decode credentials")
		return nil, err
	}
	s, serr := vaultClient.GetKVSecretRetry(k8screds.ClusterName + "/" + id.ID)
	if serr != nil {
		l.WithError(serr).Error("GetK8SSSAFromVault failed")
		return s, serr
	}
	id.Credentials = s
	return id.Credentials, nil
}
