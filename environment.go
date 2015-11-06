// ThreatSpec package controller
package controller

import (
	log "github.com/cihub/seelog"
	"github.com/pki-io/core/api"
	"github.com/pki-io/core/fs"
	"os"
)

type Environment struct {
	logger log.LoggerInterface
	fs     struct {
		local *fs.Local
		home  *fs.Home
	}
	api         api.Apier
	controllers struct {
		org   *OrgController
		admin *AdminController
		node  *NodeController
	}
}

func NewEnvironment(logger log.LoggerInterface) *Environment {
	env := new(Environment)
	env.logger = logger
	return env
}

func (env *Environment) Fatal(err error) {
	env.logger.Critical(err)
	os.Exit(1)
}

func (env *Environment) LoadLocalFs() error {
	env.logger.Debug("loading local file system")
	var err error
	env.fs.local, err = fs.NewLocal(os.Getenv("PKIIO_LOCAL"))
	if err != nil {
		return err
	}
	return nil
}

func (env *Environment) LoadHomeFs() error {
	env.logger.Debug("loading home file system")
	var err error
	if env.fs.home, err = fs.NewHome(os.Getenv("PKIIO_HOME")); err != nil {
		return err
	}
	return nil
}

func (env *Environment) LoadAPI() error {
	env.logger.Debug("loading API")
	var err error
	if env.api, err = fs.NewAPI(env.fs.local.Path); err != nil {
		return err
	}
	return nil
}

// ThreatSpec TMv0.1 for Environment.LoadPrivateOrg
// It loads public org for App:Org

func (env *Environment) LoadPublicOrg() error {
	env.logger.Debug("loading public org")
	var err error

	env.logger.Debug("initializing org controller")
	if env.controllers.org == nil {
		if env.controllers.org, err = NewOrg(env); err != nil {
			return err
		}
	}

	if err := env.controllers.org.LoadConfig(); err != nil {
		return err
	}

	if err := env.controllers.org.LoadPublicOrg(); err != nil {
		return err
	}

	return nil
}

/*func (env *Environment) LoadPublicNodeOrg() error {
	var err error

	env.logger.Debug("Initializing node controller")
	if env.controllers.node == nil {
		if env.controllers.node, err = NewNodeController(env); err != nil {
			return err
		}
	}

	env.logger.Debug("Loading node config")
	if err := env.controllers.node.LoadConfig(); err != nil {
		return err
	}

	env.logger.Debug("Loading public org")
	if err := env.controllers.node.LoadPublicOrg(); err != nil {
		return err
	}

	return nil
}*/

// ThreatSpec TMv0.1 for Environment.LoadPrivateOrg
// It loads private org for App:Org

func (env *Environment) LoadPrivateOrg() error {
	env.logger.Debug("loading private org")

	var err error
	if env.controllers.org == nil {
		env.controllers.org, err = NewOrg(env)
		if err != nil {
			return err
		}
	}

	if err := env.controllers.org.LoadConfig(); err != nil {
		return err
	}

	if err := env.controllers.org.LoadPrivateOrg(); err != nil {
		return err
	}

	return nil
}

// ThreatSpec TMv0.1 for Environment.LoadAdmin
// It loads admin config and entity for App:Admin

func (env *Environment) LoadAdmin() error {
	env.logger.Debug("loading admin")

	var err error
	if env.controllers.admin == nil {
		env.controllers.admin, err = NewAdmin(env)
		if err != nil {
			return err
		}
	}

	if err := env.controllers.admin.LoadConfig(); err != nil {
		return err
	}

	if err := env.controllers.admin.LoadAdmin(); err != nil {
		return err
	}

	return nil
}

// ThreatSpec TMv0.1 for Environment.LoadAdminEnv
// It loads admin environment for App:Admin

func (env *Environment) LoadAdminEnv() error {
	env.logger.Debug("loading admin environment")

	if err := env.LoadLocalFs(); err != nil {
		return err
	}

	if err := env.LoadHomeFs(); err != nil {
		return err
	}

	if err := env.LoadAPI(); err != nil {
		return err
	}

	if err := env.LoadPublicOrg(); err != nil {
		return err
	}

	if err := env.LoadAdmin(); err != nil {
		return err
	}

	if err := env.LoadPrivateOrg(); err != nil {
		return err
	}

	return nil
}

func (env *Environment) LoadNodeEnv() error {
	env.logger.Debug("loading node environment")

	if err := env.LoadLocalFs(); err != nil {
		return err
	}

	if err := env.LoadHomeFs(); err != nil {
		return err
	}

	if err := env.LoadAPI(); err != nil {
		return err
	}

	// Assumes this already exists
	if err := env.LoadPublicOrg(); err != nil {
		return err
	}

	return nil
}
