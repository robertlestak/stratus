package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/robertlestak/stratus/internal/config"
	"github.com/robertlestak/stratus/internal/identity"
	"github.com/robertlestak/stratus/internal/vaultclient"
	log "github.com/sirupsen/logrus"
)

// newRequestID returns a uuid
func newRequestID() string {
	return uuid.New().String()
}

// handleIdentityRequest handles the identity request
func handleIdentityRequest(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"func": "handleIdentityRequest",
	})
	l.Info("start")
	var mm identity.IAMMap
	defer r.Body.Close()
	// set request id to header
	mm.RequestID = r.Header.Get("x-request-id")
	// if request id does not exist create one
	if mm.RequestID == "" {
		mm.RequestID = newRequestID()
	}
	// set request ids on source and target for tracing
	mm.Source.RequestID = mm.RequestID
	mm.Target.RequestID = mm.RequestID
	l = l.WithFields(log.Fields{
		"requestId": mm.RequestID,
	})
	l.Info("get requestId")
	// decode body into an IAMMap
	jerr := json.NewDecoder(r.Body).Decode(&mm)
	if jerr != nil {
		l.Printf("%+v", jerr)
		w.Header().Add("x-request-id", mm.RequestID)
		http.Error(w, jerr.Error(), http.StatusBadRequest)
		return
	}
	// check if source is valid with its cloud provider
	if !mm.Source.Valid() {
		l.Errorf("%+v", errors.New("invalid source identity"))
		w.Header().Add("x-request-id", mm.RequestID)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// find matching config block for source and target
	i, ierr := mm.FindIDinMap(config.IdMaps)
	if ierr != nil {
		l.Printf("%+v", ierr)
		w.Header().Add("x-request-id", mm.RequestID)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// config block was found and returned clean from config, re-add request id and source credentials
	i.Source.RequestID = mm.RequestID
	i.Target.RequestID = mm.RequestID
	i.Source.Credentials = mm.Source.Credentials
	mm.Target.Credentials = i.Target.Credentials
	// retrieve the credentials for the target identity
	c, cerr := mm.GetCredentials(vaultclient.Client)
	if cerr != nil {
		l.Printf("%+v", cerr)
		w.Header().Add("x-request-id", mm.RequestID)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// return target credentials to the client
	i.Target.Credentials = c
	jd, jerr := json.Marshal(i.Target.Credentials)
	if jerr != nil {
		l.Printf("%+v", jerr)
		w.Header().Add("x-request-id", mm.RequestID)
		http.Error(w, jerr.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Add("x-request-id", mm.RequestID)
	w.Write(jd)
}

// init initializes the application
func init() {
	// create vault client from environment
	c := &vaultclient.VaultClient{
		VaultAddr:  os.Getenv("VAULT_ADDR"),
		Token:      os.Getenv("VAULT_TOKEN"),
		Role:       os.Getenv("VAULT_ROLE"),
		AuthMethod: os.Getenv("VAULT_AUTH_METHOD"),
	}
	// initialize global vault client
	_, err := c.NewClient()
	if err != nil {
		log.Fatal(err)
	}
	// monitor git repo, pull changes, and update config on changes
	go config.RefreshSyncConfigs()
}

// main is the entry point for the application
func main() {
	l := log.WithFields(log.Fields{
		"func": "main",
	})
	l.Info("start")
	r := mux.NewRouter()
	r.HandleFunc("/", handleIdentityRequest).Methods("POST")
	http.ListenAndServe(":"+os.Getenv("PORT"), r)
}
