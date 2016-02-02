// ThreatSpec package controller
package controller

import (
	"fmt"
	"github.com/pki-io/core/crypto"
	"github.com/pki-io/core/document"
	"github.com/pki-io/core/fs"
	"github.com/pki-io/core/x509"
	"time"
)

type CAController struct {
	env *Environment
}

func NewCA(env *Environment) (*CAController, error) {
	cont := new(CAController)
	cont.env = env
	return cont, nil
}

func (cont *CAController) GetCA(id string) (*x509.CA, error) {
	logger.Debugf("getting CA")
	logger.Tracef("received id '%s", id)

	logger.Debugf("getting CA json '%s' for org '%s'", id, cont.env.controllers.org.OrgId())
	caContainerJson, err := cont.env.api.GetPrivate(cont.env.controllers.org.OrgId(), id)
	if err != nil {
		return nil, err
	}

	logger.Debug("creating new container from json")
	caContainer, err := document.NewContainer(caContainerJson)
	if err != nil {
		return nil, err
	}

	logger.Debug("decrypting container")
	caJson, err := cont.env.controllers.org.org.VerifyThenDecrypt(caContainer)
	if err != nil {
		return nil, err
	}

	logger.Debug("loading CA json to struct")
	ca, err := x509.NewCA(caJson)
	if err != nil {
		return nil, err
	}

	logger.Trace("returning CA")
	return ca, nil
}

func (cont *CAController) SaveCA(ca *x509.CA) error {
	logger.Debug("saving CA")
	logger.Trace("received CA [NOT LOGGED]")

	logger.Debug("encrypting CA for org")
	caContainer, err := cont.env.controllers.org.org.EncryptThenSignString(ca.Dump(), nil)
	if err != nil {
		return err
	}

	logger.Debug("saving encrypted CA")
	err = cont.env.api.SendPrivate(cont.env.controllers.org.org.Data.Body.Id, ca.Data.Body.Id, caContainer.Dump())
	if err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}

func (cont *CAController) ResetCATags(caId, tags string) error {
	logger.Debug("resetting CA tags")
	logger.Tracef("received caId '%s' and tags '%s", caId, tags)

	orgIndex, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return err
	}

	if err := orgIndex.ClearCATags(caId); err != nil {
		return err
	}

	err = orgIndex.AddCATags(caId, ParseTags(tags))
	if err != nil {
		return err
	}

	err = cont.env.controllers.org.SaveIndex(orgIndex)
	if err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}

func (cont *CAController) AddCAToOrgIndex(ca *x509.CA, tags string) error {
	logger.Debug("Adding CA to org index")
	logger.Tracef("received ca [NOT LOGGED] with tags '%s'", tags)

	orgIndex, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return err
	}

	err = orgIndex.AddCA(ca.Data.Body.Name, ca.Data.Body.Id)
	if err != nil {
		return err
	}

	err = orgIndex.AddCATags(ca.Data.Body.Id, ParseTags(tags))
	if err != nil {
		return err
	}

	err = cont.env.controllers.org.SaveIndex(orgIndex)
	if err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}

func (cont *CAController) RemoveCAFromOrgIndex(name string) error {
	logger.Debug("removing CA from org index")
	logger.Tracef("received name '%s'", name)

	orgIndex, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return err
	}

	if err := orgIndex.RemoveCA(name); err != nil {
		return err
	}

	err = cont.env.controllers.org.SaveIndex(orgIndex)
	if err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}

// ThreatSpec TMv0.1 for CAController.New
// Creates new CA for App:CAController

func (cont *CAController) New(params *CAParams) (*x509.CA, error) {
	logger.Debug("creating new CA")
	logger.Trace("received params [NOT LOGGED]")

	if err := params.ValidateName(true); err != nil {
		return nil, err
	}

	if err := params.ValidateCAExpiry(true); err != nil {
		return nil, err
	}

	if err := params.ValidateCertExpiry(true); err != nil {
		return nil, err
	}

	if err := params.ValidateKeyType(true); err != nil {
		return nil, err
	}

	if err := cont.env.LoadAdminEnv(); err != nil {
		return nil, err
	}

	logger.Debug("creating CA struct")
	ca, err := x509.NewCA(nil)
	if err != nil {
		return nil, err
	}

	ca.Data.Body.Name = *params.Name
	ca.Data.Body.CAExpiry = *params.CaExpiry
	ca.Data.Body.CertExpiry = *params.CertExpiry
	ca.Data.Body.KeyType = *params.KeyType
	ca.Data.Body.DNScope.Locality = *params.DnLocality
	ca.Data.Body.DNScope.Province = *params.DnState
	ca.Data.Body.DNScope.Organization = *params.DnOrg
	ca.Data.Body.DNScope.OrganizationalUnit = *params.DnOrgUnit
	ca.Data.Body.DNScope.Country = *params.DnCountry
	ca.Data.Body.DNScope.StreetAddress = *params.DnStreet
	ca.Data.Body.DNScope.PostalCode = *params.DnPostal

	if *params.CertFile == "" && *params.KeyFile == "" {
		logger.Debug("generating keys")
		ca.GenerateRoot()
	} else {
		if *params.CertFile == "" {
			return nil, fmt.Errorf("certificate PEM file must be provided if importing")
		}

		ok, err := fs.Exists(*params.CertFile)
		if err != nil {
			return nil, err
		}

		if !ok {
			logger.Warnf("certificate file '%s' does not exist", *params.CertFile)
			return nil, nil
		}

		logger.Debugf("reading certificate PEM file '%s", *params.CertFile)
		certPem, err := fs.ReadFile(*params.CertFile)
		if err != nil {
			return nil, err
		}

		logger.Debug("decoding certificate PEM")
		cert, err := x509.PemDecodeX509Certificate([]byte(certPem))
		if err != nil {
			return nil, err
		}

		ca.Data.Body.Id = x509.NewID()
		ca.Data.Body.Certificate = certPem
		ca.Data.Body.CertExpiry = *params.CertExpiry
		caExpiry := int(cert.NotAfter.Sub(cert.NotBefore) / (time.Hour * 24))
		ca.Data.Body.CAExpiry = caExpiry

		if *params.KeyFile != "" {
			ok, err = fs.Exists(*params.KeyFile)
			if err != nil {
				return nil, err
			}

			if !ok {
				logger.Warnf("key file '%s' does not exist", *params.KeyFile)
				return nil, nil
			}

			logger.Debugf("reading private key PEM file '%s'", *params.KeyFile)
			keyPem, err := fs.ReadFile(*params.KeyFile)
			if err != nil {
				return nil, err
			}

			logger.Debug("decoding private key")
			key, err := crypto.PemDecodePrivate([]byte(keyPem))
			if err != nil {
				return nil, err
			}

			logger.Debug("getting key type")
			keyType, err := crypto.GetKeyType(key)
			if err != nil {
				return nil, err
			}

			ca.Data.Body.KeyType = string(keyType)
			ca.Data.Body.PrivateKey = keyPem
		}
	}

	err = cont.SaveCA(ca)
	if err != nil {
		return nil, err
	}

	err = cont.AddCAToOrgIndex(ca, *params.Tags)
	if err != nil {
		return nil, err
	}

	logger.Trace("returning CA")
	return ca, nil
}

func (cont *CAController) List(params *CAParams) ([]*x509.CA, error) {
	logger.Debug("listing CAs")
	logger.Trace("received params [NOT LOGGED]")

	if err := cont.env.LoadAdminEnv(); err != nil {
		return nil, err
	}

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return nil, err
	}

	cas := make([]*x509.CA, 0)
	for _, id := range index.GetCAs() {
		ca, err := cont.GetCA(id)
		if err != nil {
			return nil, err
		}
		cas = append(cas, ca)
	}

	logger.Trace("returning CA list")
	return cas, nil
}

func (cont *CAController) Show(params *CAParams) (*x509.CA, error) {
	logger.Debug("showing CA")
	logger.Trace("received params [NOT LOGGED]")

	if err := params.ValidateName(true); err != nil {
		return nil, err
	}

	if err := params.ValidateExport(false); err != nil {
		return nil, err
	}

	if err := params.ValidatePrivate(false); err != nil {
		return nil, err
	}

	if err := cont.env.LoadAdminEnv(); err != nil {
		return nil, err
	}

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return nil, err
	}

	caId, err := index.GetCA(*params.Name)
	if err != nil {
		return nil, err
	}

	ca, err := cont.GetCA(caId)
	if err != nil {
		return nil, err
	}

	logger.Trace("returning CA")
	return ca, nil
}

func (cont *CAController) Update(params *CAParams) error {
	logger.Debug("updating CA")
	logger.Trace("received params [NOT LOGGED]")

	if err := params.ValidateName(true); err != nil {
		return err
	}

	if err := cont.env.LoadAdminEnv(); err != nil {
		return err
	}

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return err
	}

	caId, err := index.GetCA(*params.Name)
	if err != nil {
		return err
	}

	ca, err := cont.GetCA(caId)
	if err != nil {
		return err
	}

	if *params.CertFile != "" {
		ok, err := fs.Exists(*params.CertFile)
		if err != nil {
			return err
		}
		if !ok {
			logger.Warnf("certificate file '%s' does not exist", *params.CertFile)
			return nil
		}

		logger.Debugf("reading certificate file '%s'", *params.CertFile)
		certPem, err := fs.ReadFile(*params.CertFile)
		if err != nil {
			return err
		}

		// TODO - better validation of pem
		logger.Debug("decoding certificate file PEM")
		_, err = x509.PemDecodeX509Certificate([]byte(certPem))
		if err != nil {
			return err
		}

		logger.Trace("setting certificate")
		ca.Data.Body.Certificate = certPem
	}

	if *params.KeyFile != "" {
		ok, err := fs.Exists(*params.KeyFile)
		if err != nil {
			return err
		}
		if !ok {
			logger.Warnf("key file '%s' does not exist", *params.KeyFile)
			return nil
		}

		logger.Debugf("seading key file '%s'", *params.KeyFile)
		keyPem, err := fs.ReadFile(*params.KeyFile)
		if err != nil {
			return err
		}

		// TODO - better validation of pem
		logger.Debug("decoding key file PEM")
		key, err := crypto.PemDecodePrivate([]byte(keyPem))
		if err != nil {
			return err
		}

		logger.Debug("getting key type")
		keyType, err := crypto.GetKeyType(key)
		if err != nil {
			return err
		}

		ca.Data.Body.KeyType = string(keyType)
		ca.Data.Body.PrivateKey = keyPem
	}

	if *params.Tags != "" {
		cont.ResetCATags(caId, *params.Tags)
	}

	if *params.CaExpiry != 0 {
		logger.Tracef("setting CA expiry to %d", *params.CaExpiry)
		ca.Data.Body.CAExpiry = *params.CaExpiry
	}

	if *params.CertExpiry != 0 {
		logger.Tracef("setting certificate expiry to %d", *params.CertExpiry)
		ca.Data.Body.CertExpiry = *params.CertExpiry
	}

	if *params.DnLocality != "" {
		logger.Tracef("setting DN locality to %s", *params.DnLocality)
		ca.Data.Body.DNScope.Locality = *params.DnLocality
	}

	if *params.DnState != "" {
		logger.Tracef("setting DN state to %s", *params.DnState)
		ca.Data.Body.DNScope.Province = *params.DnState
	}

	if *params.DnOrg != "" {
		logger.Tracef("setting DN organisation to %s", *params.DnOrg)
		ca.Data.Body.DNScope.Organization = *params.DnOrg
	}

	if *params.DnOrgUnit != "" {
		logger.Tracef("setting DN organisational unit to %s", *params.DnOrgUnit)
		ca.Data.Body.DNScope.OrganizationalUnit = *params.DnOrgUnit
	}

	if *params.DnCountry != "" {
		logger.Tracef("setting DN country to %s", *params.DnCountry)
		ca.Data.Body.DNScope.Country = *params.DnCountry
	}

	if *params.DnStreet != "" {
		logger.Tracef("setting DN street address to %s", *params.DnStreet)
		ca.Data.Body.DNScope.StreetAddress = *params.DnStreet
	}

	if *params.DnPostal != "" {
		logger.Tracef("setting DN postal code to %s", *params.DnPostal)
		ca.Data.Body.DNScope.PostalCode = *params.DnPostal
	}

	err = cont.SaveCA(ca)
	if err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}

func (cont *CAController) Delete(params *CAParams) error {
	logger.Debug("deleting CA")
	logger.Tracef("received params: %s", params)

	if err := params.ValidateName(true); err != nil {
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

	caId, err := index.GetCA(*params.Name)
	if err != nil {
		return err
	}

	logger.Debugf("deleting private file for CA '%s' in org '%s'", caId, cont.env.controllers.org.OrgId())
	if err := cont.env.api.DeletePrivate(cont.env.controllers.org.OrgId(), caId); err != nil {
		return err
	}

	if err := index.RemoveCA(*params.Name); err != nil {
		return err
	}

	err = cont.env.controllers.org.SaveIndex(index)
	if err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}
