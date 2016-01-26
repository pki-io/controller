// ThreatSpec package controller
package controller

import (
	"fmt"
	"github.com/pki-io/core/config"
	"github.com/pki-io/core/document"
	"github.com/pki-io/core/entity"
	"github.com/pki-io/core/x509"
)

const (
	ConfigFile string = "admin.conf"
)

type AdminController struct {
	env    *Environment
	config *config.AdminConfig
	admin  *entity.Entity
}

func NewAdmin(env *Environment) (*AdminController, error) {
	cont := new(AdminController)
	cont.env = env

	return cont, nil
}

func (cont *AdminController) SetEnv(env *Environment) error {
	if env == nil {
		return fmt.Errorf("env cannot be nil")
	}

	cont.env = env
	return nil
}

func (cont *AdminController) GetEnv() (*Environment, error) {
	if cont.env == nil {
		return nil, fmt.Errorf("nil env")
	}
	return cont.env, nil
}

// ThreatSpec TMv0.1 for AdminController.LoadConfig
// It loads admin config from filesystem for App:

func (cont *AdminController) LoadConfig() error {
	cont.env.logger.Debug("loading admin config")
	var err error
	if cont.config == nil {
		cont.config, err = config.NewAdmin()
		if err != nil {
			return err
		}
	}

	cont.env.logger.Debugf("checking file '%s' exists", ConfigFile)
	exists, err := cont.env.fs.home.Exists(ConfigFile)
	if err != nil {
		return err
	}

	if exists {
		cont.env.logger.Debug("reading config file")
		adminConfig, err := cont.env.fs.home.Read(ConfigFile)
		if err != nil {
			return err
		}

		cont.env.logger.Debug("loading config")
		err = cont.config.Load(adminConfig)
		if err != nil {
			return err
		}
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *AdminController) SaveConfig() error {
	cont.env.logger.Debug("saving admin config")
	cfgString, err := cont.config.Dump()
	if err != nil {
		return err
	}

	cont.env.logger.Debugf("writing config to file '%s", ConfigFile)
	if err := cont.env.fs.home.Write(ConfigFile, cfgString); err != nil {
		return err
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *AdminController) CreateAdmin(name string) error {
	cont.env.logger.Debug("creating new admin")
	var err error

	// TODO validate name

	cont.env.logger.Debug("creating new entity")
	cont.admin, err = entity.New(nil)
	if err != nil {
		return err
	}

	cont.admin.Data.Body.Id = x509.NewID()
	cont.admin.Data.Body.Name = name

	cont.env.logger.Debug("generating keys")
	err = cont.admin.GenerateKeys()
	if err != nil {
		return err
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *AdminController) LoadAdmin() error {
	cont.env.logger.Debug("loading admin")
	orgName := cont.env.controllers.org.config.Data.Name

	adminOrgConfig, err := cont.config.GetOrg(orgName)
	if err != nil {
		return err
	}

	adminId := adminOrgConfig.AdminId

	cont.env.logger.Debugf("reading file for admin id '%s'", adminId)
	adminEntity, err := cont.env.fs.home.Read(adminId)
	if err != nil {
		return err
	}

	cont.env.logger.Debug("creating entity")
	cont.admin, err = entity.New(adminEntity)
	if err != nil {
		return err
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *AdminController) GetAdmin(id string) (*entity.Entity, error) {
	cont.env.logger.Debug("getting admin")
	cont.env.logger.Tracef("received id '%s'", id)

	adminJson, err := cont.env.api.GetPublic(id, id)
	if err != nil {
		return nil, err
	}

	cont.env.logger.Debug("creating entity")
	admin, err := entity.New(adminJson)
	if err != nil {
		return nil, err
	}

	cont.env.logger.Trace("returning admin")
	return admin, nil
}

func (cont *AdminController) GetAdmins() ([]entity.Encrypter, error) {
	cont.env.logger.Debug("getting admins")

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return nil, err
	}

	adminIds, err := index.GetAdmins()
	if err != nil {
		return nil, err
	}

	admins := make([]entity.Encrypter, 0, 0)
	for _, id := range adminIds {
		admin, err := cont.GetAdmin(id)
		if err != nil {
			return nil, err
		}

		admins = append(admins, admin)
	}

	cont.env.logger.Trace("returning admin list")
	return admins, nil
}

func (cont *AdminController) SaveAdmin() error {
	cont.env.logger.Debug("saving admin")
	id := cont.admin.Data.Body.Id

	cont.env.logger.Debugf("saving private admin '%s' to home", id)
	if err := cont.env.fs.home.Write(id, cont.admin.Dump()); err != nil {
		return err
	}

	// Send a public admin
	cont.env.logger.Debugf("sending public admin '%s'", id)
	if err := cont.env.api.SendPublic(id, id, cont.admin.DumpPublic()); err != nil {
		return err
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *AdminController) SendOrgEntity() error {
	cont.env.logger.Debug("sending org")

	org := cont.env.controllers.org.org

	admins, err := cont.GetAdmins()
	if err != nil {
		return err
	}

	cont.env.logger.Debug("encrypting private org for admins")
	container, err := org.EncryptThenSignString(org.Dump(), admins)
	if err != nil {
		return err
	}

	cont.env.logger.Debugf("sending private org '%s'", org.Id())
	if err := cont.env.api.SendPrivate(org.Id(), org.Id(), container.Dump()); err != nil {
		return err
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *AdminController) SecureSendPublicToOrg(id, key string) error {
	cont.env.logger.Debugf("secure sending public admin to org")
	cont.env.logger.Tracef("received id '%s' and key [NOT LOGGED]", id)

	orgId := cont.env.controllers.org.config.Data.Id

	cont.env.logger.Debug("encrypting public admin invite for org")
	container, err := cont.admin.EncryptThenAuthenticateString(cont.admin.DumpPublic(), id, key)
	if err != nil {
		return err
	}

	cont.env.logger.Debugf("pushing admin invite to org '%s'", orgId)
	if err := cont.env.api.PushIncoming(orgId, "invite", container.Dump()); err != nil {
		return err
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *AdminController) ProcessNextInvite() error {

	org := cont.env.controllers.org.org

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return err
	}

	inviteJson, err := cont.env.api.PopIncoming(org.Id(), "invite")
	if err != nil {
		return err
	}

	container, err := document.NewContainer(inviteJson)
	if err != nil {
		cont.env.api.PushIncoming(org.Id(), "invite", inviteJson)
		return err
	}

	inviteId := container.Data.Options.SignatureInputs["key-id"]
	cont.env.logger.Debugf("Reading invite key: %s", inviteId)
	inviteKey, err := index.GetInviteKey(inviteId)
	if err != nil {
		cont.env.api.PushIncoming(org.Id(), "invite", inviteJson)
		return err
	}

	cont.env.logger.Debug("Verifying and decrypting admin invite")
	adminJson, err := org.VerifyAuthenticationThenDecrypt(container, inviteKey.Key)
	if err != nil {
		cont.env.api.PushIncoming(org.Id(), "invite", inviteJson)
		return err
	}

	admin, err := entity.New(adminJson)
	if err != nil {
		cont.env.api.PushIncoming(org.Id(), "invite", inviteJson)
		return err
	}

	if err := index.AddAdmin(admin.Data.Body.Name, admin.Data.Body.Id); err != nil {
		return err
	}

	if err := cont.env.controllers.org.SaveIndex(index); err != nil {
		return err
	}

	if err := cont.SendOrgEntity(); err != nil {
		return err
	}

	orgContainer, err := cont.admin.EncryptThenAuthenticateString(org.DumpPublic(), inviteId, inviteKey.Key)
	if err != nil {
		return err
	}

	if err := cont.env.api.PushIncoming(admin.Data.Body.Id, "invite", orgContainer.Dump()); err != nil {
		return err
	}

	// Delete invite ID

	return nil
}

func (cont *AdminController) ProcessInvites() error {
	cont.env.logger.Debug("Processing invites")

	org := cont.env.controllers.org.org

	for {
		size, err := cont.env.api.IncomingSize(org.Id(), "invite")
		if err != nil {
			return err
		}

		cont.env.logger.Debugf("Found %d invites to process", size)

		if size > 0 {
			if err := cont.ProcessNextInvite(); err != nil {
				return err
			}
		} else {
			break
		}
	}

	return nil
}

func (cont *AdminController) ShowEnv(params *AdminParams) (*entity.Entity, error) {
	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return nil, err
	}

	adminId, err := index.GetAdmin(*params.Name)
	if err != nil {
		return nil, err
	}

	admin, err := cont.GetAdmin(adminId)
	if err != nil {
		return nil, err
	}

	return admin, nil
}

func (cont *AdminController) InviteEnv(params *AdminParams) ([2]string, error) {

	cont.env.logger.Debug("Creating new admin key")
	id := x509.NewID()
	key := x509.NewID()

	cont.env.logger.Debug("Saving key to index")
	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return [2]string{}, err
	}

	index.AddInviteKey(id, key, *params.Name)

	if err := cont.env.controllers.org.SaveIndex(index); err != nil {
		return [2]string{}, err
	}

	return [2]string{id, key}, nil
}

func (cont *AdminController) RunEnv(params *AdminParams) error {

	if err := cont.ProcessInvites(); err != nil {
		return err
	}

	return nil
}

func (cont *AdminController) List(params *AdminParams) ([]*entity.Entity, error) {
	cont.env.logger.Tracef("received params: %s", params)

	if err := cont.env.LoadAdminEnv(); err != nil {
		return nil, err
	}

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return nil, err
	}

	adminList, err := index.GetAdmins()
	if err != nil {
		return nil, err
	}

	admins := make([]*entity.Entity, 0)
	for _, id := range adminList {
		admin, err := cont.GetAdmin(id)
		if err != nil {
			return nil, err
		}
		admins = append(admins, admin)
	}

	return admins, nil
}

func (cont *AdminController) Show(params *AdminParams) (*entity.Entity, error) {
	cont.env.logger.Tracef("received params: %s", params)
	cont.env.logger.Debug("Validating parameters")

	if err := params.ValidateName(true); err != nil {
		return nil, err
	}

	if err := cont.env.LoadAdminEnv(); err != nil {
		return nil, err
	}

	return cont.env.controllers.admin.ShowEnv(params)
}

func (cont *AdminController) Invite(params *AdminParams) ([2]string, error) {
	cont.env.logger.Tracef("received params: %s", params)

	cont.env.logger.Debug("Validating parameters")

	if err := params.ValidateName(true); err != nil {
		return [2]string{}, err
	}

	cont.env.logger.Debug("Loading admin environment")

	if err := cont.env.LoadAdminEnv(); err != nil {
		return [2]string{}, err
	}

	return cont.env.controllers.admin.InviteEnv(params)
}

func (cont *AdminController) New(params *AdminParams) error {
	cont.env.logger.Tracef("received params: %s", params)

	var err error

	cont.env.logger.Debug("Validating parameters")

	if err := params.ValidateName(true); err != nil {
		return err
	}

	cont.env.logger.Debug("Loading local filesystem")
	if err := cont.env.LoadLocalFs(); err != nil {
		return err
	}

	cont.env.logger.Debug("Loading home filesystem")
	if err := cont.env.LoadHomeFs(); err != nil {
		return err
	}

	cont.env.logger.Debug("Loading API")
	if err := cont.env.LoadAPI(); err != nil {
		return err
	}

	cont.env.logger.Debug("Initializing org controller")
	if cont.env.controllers.org == nil {
		if cont.env.controllers.org, err = NewOrg(cont.env); err != nil {
			return err
		}
	}

	cont.env.logger.Debug("Loading org config")
	if err := cont.env.controllers.org.LoadConfig(); err != nil {
		return err
	}

	cont.env.logger.Debug("Creating admin entity")
	cont.admin, err = entity.New(nil)
	if err != nil {
		return nil
	}

	cont.admin.Data.Body.Id = x509.NewID()
	cont.admin.Data.Body.Name = *params.Name

	cont.env.logger.Debug("Generating admin keys")
	if err := cont.admin.GenerateKeys(); err != nil {
		return err
	}

	if err := cont.SaveAdmin(); err != nil {
		return nil
	}

	if err := cont.LoadConfig(); err != nil {
		return err
	}

	orgId := cont.env.controllers.org.config.Data.Id
	orgName := cont.env.controllers.org.config.Data.Name

	if err := cont.config.AddOrg(orgName, orgId, cont.admin.Id()); err != nil {
		return err
	}

	if err := cont.SaveConfig(); err != nil {
		return err
	}

	if err := cont.SecureSendPublicToOrg(*params.InviteId, *params.InviteKey); err != nil {
		return err
	}

	return nil
}

func (cont *AdminController) Run(params *AdminParams) error {
	cont.env.logger.Tracef("received params: %s", params)

	if err := cont.env.LoadAdminEnv(); err != nil {
		return err
	}

	return cont.env.controllers.admin.RunEnv(params)
}

func (cont *AdminController) Complete(params *AdminParams) error {

	var err error
	cont.env.logger.Tracef("received params: %s", params)

	cont.env.logger.Debug("validating parameters")

	if err := cont.env.LoadLocalFs(); err != nil {
		return err
	}

	if err := cont.env.LoadHomeFs(); err != nil {
		return err
	}

	if err := cont.env.LoadAPI(); err != nil {
		return err
	}

	cont.env.logger.Debug("Initializing org controller")
	if cont.env.controllers.org == nil {
		if cont.env.controllers.org, err = NewOrg(cont.env); err != nil {
			return err
		}
	}

	if err := cont.env.controllers.org.LoadConfig(); err != nil {
		return err
	}

	if err := cont.LoadConfig(); err != nil {
		return err
	}

	if err := cont.LoadAdmin(); err != nil {
		return err
	}

	orgContainerJson, err := cont.env.api.PopIncoming(cont.admin.Data.Body.Id, "invite")
	if err != nil {
		return err
	}

	orgContainer, err := document.NewContainer(orgContainerJson)
	if err != nil {
		return err
	}

	orgJson, err := cont.admin.VerifyAuthenticationThenDecrypt(orgContainer, *params.InviteKey)
	if err != nil {
		return err
	}

	org, err := entity.New(orgJson)
	if err != nil {
		return err
	}

	cont.env.logger.Debug("Saving public org to home")
	if err := cont.env.fs.home.Write(org.Data.Body.Id, org.DumpPublic()); err != nil {
		return err
	}

	return nil
}

func (cont *AdminController) Delete(params *AdminParams) error {
	cont.env.logger.Tracef("received params: %s", params)

	if err := cont.env.LoadAdminEnv(); err != nil {
		return err
	}

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return err
	}

	if err := index.RemoveAdmin(*params.Name); err != nil {
		return err
	}

	if err := cont.env.controllers.org.SaveIndex(index); err != nil {
		return err
	}

	if err := cont.SendOrgEntity(); err != nil {
		return err
	}

	return nil
}
