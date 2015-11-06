// ThreatSpec package controller
package controller

import (
	"github.com/pki-io/core/x509"
	"strings"
)

type PairingKeyController struct {
	env *Environment
}

func NewPairingKey(env *Environment) (*PairingKeyController, error) {
	cont := new(PairingKeyController)
	cont.env = env
	return cont, nil
}

func (cont *PairingKeyController) GeneratePairingKey() (string, string) {
	cont.env.logger.Debug("generating pairing key")
	id := x509.NewID()
	key := x509.NewID()

	cont.env.logger.Trace("returning pairing key")
	return id, key
}

func (cont *PairingKeyController) AddPairingKeyToOrgIndex(id, key, tags string) error {
	cont.env.logger.Debug("adding pairing key to org index")
	cont.env.logger.Tracef("received id '%s', key [NOT LOGGED], and tags '%s'", id, tags)

	orgIndex, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return err
	}

	if err := orgIndex.AddPairingKey(id, key, ParseTags(tags)); err != nil {
		return err
	}

	err = cont.env.controllers.org.SaveIndex(orgIndex)
	if err != nil {
		return err
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *PairingKeyController) New(params *PairingKeyParams) (string, string, error) {
	cont.env.logger.Debug("creating new pairing key")
	cont.env.logger.Tracef("received params: %s", params)

	if err := params.ValidateTags(true); err != nil {
		return "", "", err
	}

	if err := cont.env.LoadAdminEnv(); err != nil {
		return "", "", err
	}

	id, key := cont.GeneratePairingKey()

	err := cont.AddPairingKeyToOrgIndex(id, key, *params.Tags)
	if err != nil {
		return "", "", err
	}

	cont.env.logger.Trace("returning pairing key")
	return id, key, nil
}

func (cont *PairingKeyController) List(params *PairingKeyParams) ([][]string, error) {
	cont.env.logger.Debug("listing pairing keys")
	cont.env.logger.Tracef("received params: %s", params)

	keys := [][]string{}

	if err := cont.env.LoadAdminEnv(); err != nil {
		return keys, err
	}

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return keys, err
	}

	cont.env.logger.Flush()
	for id, pk := range index.GetPairingKeys() {
		keys = append(keys, []string{id, strings.Join(pk.Tags[:], ",")})
	}

	cont.env.logger.Trace("returning keys")
	return keys, nil
}

func (cont *PairingKeyController) Show(params *PairingKeyParams) (string, string, string, error) {
	cont.env.logger.Debug("showing pairing key")
	cont.env.logger.Tracef("received params: %s", params)

	if err := params.ValidateID(true); err != nil {
		return "", "", "", err
	}

	if err := cont.env.LoadAdminEnv(); err != nil {
		return "", "", "", err
	}

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return "", "", "", err
	}

	pk, err := index.GetPairingKey(*params.Id)
	if err != nil {
		return "", "", "", err
	}

	cont.env.logger.Trace("returning pairing key")
	return *params.Id, pk.Key, strings.Join(pk.Tags[:], ","), nil
}

func (cont *PairingKeyController) Delete(params *PairingKeyParams) error {
	cont.env.logger.Debug("deleting pairing key")
	cont.env.logger.Tracef("received params: %s", params)

	if err := params.ValidateID(true); err != nil {
		return err
	}

	if err := params.ValidateConfirmDelete(true); err != nil {
		return err
	}

	if err := cont.env.LoadAdminEnv(); err != nil {
		return err
	}

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return err
	}

	if err := index.RemovePairingKey(*params.Id); err != nil {
		return err
	}

	err = cont.env.controllers.org.SaveIndex(index)
	if err != nil {
		return err
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}
