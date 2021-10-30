package config

import (
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/robertlestak/stratus/internal/identity"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var (
	IdMaps []identity.IAMMap
)

func gitClone(p string, cd string) (*git.Repository, error) {
	l := log.WithFields(
		log.Fields{
			"package": "config",
			"func":    "gitClone",
		})

	l.Info("Cloning git repository")
	r, err := git.PlainClone(cd, false, &git.CloneOptions{
		URL:               p,
		Auth:              &http.BasicAuth{Username: "devops", Password: os.Getenv("GITHUB_TOKEN")},
		RemoteName:        "origin",
		ReferenceName:     plumbing.ReferenceName(os.Getenv("REMOTE_GIT_REF")),
		SingleBranch:      false,
		NoCheckout:        false,
		Depth:             0,
		RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
		Progress:          nil,
		Tags:              0,
		InsecureSkipTLS:   false,
		CABundle:          []byte{},
	})
	if err != nil {
		l.WithError(err).Error("failed to pull remote config")
		return r, err
	}
	return r, nil
}

func pullRemoteConfig(p string) error {
	l := log.WithFields(
		log.Fields{
			"action": "pullRemoteConfig",
			"path":   p,
		})
	l.Info("pulling remote config")
	cd := os.Getenv("GIT_CLONE_DIR")
	l.Info("pulled remote config")
	var r *git.Repository
	var err error
	if s, err := os.Stat(cd); os.IsNotExist(err) || !s.IsDir() {
		l.Info("Cloning git repository")
		r, err = gitClone(p, cd)
		if err != nil {
			l.WithError(err).Error("failed to pull remote config")
			return err
		}
		l.Info("pulled remote config")
	} else {
		l.Info("pulling remote config")
		r, err = git.PlainOpen(cd)
		if err != nil {
			l.WithError(err).Error("failed to pull remote config")
			return err
		}
		w, err := r.Worktree()
		if err != nil {
			l.WithError(err).Error("failed to pull remote config")
			return err
		}
		err = w.Pull(&git.PullOptions{
			RemoteName:        "origin",
			ReferenceName:     plumbing.ReferenceName(os.Getenv("REMOTE_GIT_REF")),
			SingleBranch:      false,
			Depth:             0,
			Auth:              &http.BasicAuth{Username: "devops", Password: os.Getenv("GITHUB_TOKEN")},
			RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
			Progress:          nil,
			Force:             false,
			InsecureSkipTLS:   false,
			CABundle:          []byte{},
		})
		if err != nil && err != git.NoErrAlreadyUpToDate {
			l.WithError(err).Error("failed to pull remote config")
			return err
		}
		l.Info("pulled remote config")
	}
	ref, err := r.Head()
	if err != nil {
		l.WithError(err).Error("failed to get head")
		return err
	}
	commit, err := r.CommitObject(ref.Hash())
	if err != nil {
		l.WithError(err).Error("failed to get commit")
		return err
	}
	l.WithField("commit", commit.Hash.String()).Info("got commit")
	return nil
}

func loadConfigPaths(cps []string) ([]identity.IAMMap, error) {
	l := log.WithFields(log.Fields{
		"action": "loadConfigPaths",
	})
	l.Info("start")
	var sc []identity.IAMMap
	for _, cp := range cps {
		l.Infof("loading config from %s", cp)
		var tsc []identity.IAMMap
		fd, ferr := ioutil.ReadFile(cp)
		if ferr != nil {
			l.WithError(ferr).Error("failed to read config file")
			return sc, ferr
		}
		err := yaml.Unmarshal(fd, &tsc)
		if err != nil {
			l.WithError(err).Error("failed to unmarshal config file")
			return sc, err
		}
		l.Infof("cfg=%+v", tsc)
		l.Infof("loaded %d sync configs", len(sc))
		for _, v := range tsc {
			l.WithFields(log.Fields{
				"config": v,
			}).Info("sync config")
		}
		sc = append(sc, tsc...)
	}
	l.Info("end")
	return sc, nil
}

func getFilesInDirRecursive(dir string) ([]string, error) {
	l := log.WithFields(log.Fields{
		"action": "getFilesInDirRecursive",
	})
	l.Info("start")
	var files []string
	err := filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return err
		}
		if f.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	})
	l.Info("end")
	return files, err
}

// loadLocalSyncConfigs loads SyncConfigs from the configuration location
func loadLocalSyncConfigs() ([]identity.IAMMap, error) {
	l := log.WithFields(log.Fields{
		"action": "createSC",
	})
	l.Info("start")
	var sc []identity.IAMMap
	cps := strings.Split(os.Getenv("CONFIG_PATHS"), ",")
	if len(cps) == 0 {
		l.Error("no config paths found")
		return sc, nil
	}
	var ncps []string
	for _, cp := range cps {
		l.Infof("loading config from %s", cp)
		tc, err := getFilesInDirRecursive(cp)
		if err != nil {
			l.Error(err)
			return sc, err
		}
		ncps = append(ncps, tc...)
	}
	cps = ncps
	l.Infof("loading configs from: %v", cps)
	sc, err := loadConfigPaths(cps)
	if err != nil {
		l.Error(err)
		return sc, err
	}
	l.Info("end")
	return sc, nil
}

// loadSyncConfigs loads the sync configs from the determined configuration location
func loadSyncConfigs() ([]identity.IAMMap, error) {
	l := log.WithFields(log.Fields{
		"action": "loadSyncConfigs",
	})
	l.Info("start")
	var sc []identity.IAMMap

	if _, err := url.ParseRequestURI(os.Getenv("REMOTE_CONFIG_REPO")); err == nil {
		l.Info("loading remote configs")
		err := pullRemoteConfig(os.Getenv("REMOTE_CONFIG_REPO"))
		if err != nil {
			l.Error(err)
			return sc, err
		}
		l.Info("loaded remote configs")
	}
	if os.Getenv("CONFIG_PATHS") != "" {
		l.Info("loading local configs")
		sc, err := loadLocalSyncConfigs()
		if err != nil {
			l.Error(err)
			return sc, err
		}
		l.Info("loaded local configs")
		return sc, nil
	}
	return sc, nil
}

// RefreshSyncConfigs refreshes the SyncConfigs from the configured location
func RefreshSyncConfigs() error {
	l := log.WithFields(log.Fields{
		"action": "refreshSyncConfigs",
	})
	pt, perr := time.ParseDuration(os.Getenv("CONFIG_REFRESH_INTERVAL"))
	if perr != nil {
		l.Fatal(perr)
		return perr
	}
	for {
		l.Info("start")
		sc, err := loadSyncConfigs()
		if err != nil {
			l.Fatal(err)
			return err
		}
		IdMaps = sc
		l.Info("end")
		time.Sleep(pt)
	}
}
