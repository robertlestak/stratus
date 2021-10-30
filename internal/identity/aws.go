package identity

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
)

// AWSCredentials contains the credentials and assumed role data
type AWSCredentials struct {
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	//Expiration      time.Time `json:"Expiration"`
}

// CreateSession creates a new session for the given role and credentials, tracking with the provided id
func CreateSession(region string, role string, creds *credentials.Credentials, id string) (*session.Session, *aws.Config, error) {
	l := log.WithFields(
		log.Fields{
			"action":    "CreateSession",
			"region":    region,
			"role":      role,
			"requestId": id,
		},
	)
	l.Print("CreateSession")
	cfg := &aws.Config{
		Region: aws.String(region),
	}
	if creds != nil {
		cfg.Credentials = creds
	}
	var sess *session.Session
	var err error
	sess, err = session.NewSession(cfg)
	if err != nil {
		l.Printf("%+v", err)
		return nil, cfg, err
	}
	if role != "" {
		l.Printf("Using role %s", role)
		creds := stscreds.NewCredentials(sess, role, func(p *stscreds.AssumeRoleProvider) {
			p.RoleSessionName = "stratus-" + id
		})
		cfg.Credentials = creds
	}
	return sess, cfg, nil
}

// stsGetCallerIdentity returns the ARN of the caller
func stsGetCallerIdentity(region string, role string, creds *credentials.Credentials, id string) (string, error) {
	l := log.WithFields(log.Fields{
		"func":      "stsGetCallerIdentity",
		"requestId": id,
	})
	l.Info("start")
	sess, cfg, err := CreateSession(region, role, creds, id)
	if err != nil {
		l.Errorf("%+v", err)
		return "", err
	}
	svc := sts.New(sess, cfg)
	input := &sts.GetCallerIdentityInput{}
	result, err := svc.GetCallerIdentity(input)
	if err != nil {
		l.Errorf("%+v", err)
		return "", err
	}
	return *result.Arn, nil
}

// ValidAWS checks if the given credentials are valid against AWS STS
func (id *Identity) ValidAWS() bool {
	l := log.WithFields(log.Fields{
		"func":      "ValidAWS",
		"requestId": id.RequestID,
	})
	l.Info("start")
	if id.Provider != "aws" {
		l.Printf("Not AWS")
		return false
	}
	var ac AWSCredentials
	err := mapstructure.Decode(id.Credentials, &ac)
	if err != nil {
		l.Errorf("mapstructure.Decode %+v", err)
		return false
	}
	if ac.AccessKeyId == "" || ac.SecretAccessKey == "" {
		l.Printf("No AccessKeyID or SecretAccessKey")
		return false
	}
	l.Info("create credentials.NewStaticCredentials")
	creds := credentials.NewStaticCredentials(
		ac.AccessKeyId,
		ac.SecretAccessKey,
		ac.SessionToken,
	)
	l.Info("create stsGetCallerIdentity")
	arn, err := stsGetCallerIdentity(id.Region, "", creds, id.RequestID)
	if err != nil {
		l.Errorf("%+v", err)
		return false
	}
	if id.ID != arn {
		l.Printf("ARN mismatch")
		return false
	}
	l.Info("id valid")
	return true
}

// CreateAWSSession creates a new session using the identity credentials
func (id *Identity) CreateAWSSession() (map[string]interface{}, error) {
	l := log.WithFields(log.Fields{
		"func":      "CreateAWSSession",
		"requestId": id.RequestID,
	})
	l.Info("CreateAWSSession")
	var ac AWSCredentials
	sess, cfg, err := CreateSession(id.Region, id.ID, nil, id.RequestID)
	if err != nil {
		l.Printf("%+v", err)
		return nil, err
	}
	svc := sts.New(sess, cfg)
	input := &sts.GetCallerIdentityInput{}
	_, err = svc.GetCallerIdentity(input)
	if err != nil {
		l.Printf("%+v", err)
		return id.Credentials, err
	}
	cd, cerr := cfg.Credentials.Get()
	if cerr != nil {
		l.Printf("%+v", cerr)
		return id.Credentials, cerr
	}
	ac = AWSCredentials{
		AccessKeyId:     cd.AccessKeyID,
		SecretAccessKey: cd.SecretAccessKey,
		SessionToken:    cd.SessionToken,
	}
	merr := mapstructure.Decode(ac, &id.Credentials)
	if merr != nil {
		l.Printf("%+v", merr)
		return id.Credentials, merr
	}
	return id.Credentials, nil
}
