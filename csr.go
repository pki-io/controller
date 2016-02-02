// ThreatSpec package controller
package controller

import (
	"crypto/x509/pkix"
	"fmt"
	"github.com/pki-io/core/crypto"
	"github.com/pki-io/core/document"
	"github.com/pki-io/core/fs"
	"github.com/pki-io/core/x509"
)

type CSRController struct {
	env *Environment
}

func NewCSR(env *Environment) (*CSRController, error) {
	cont := new(CSRController)
	cont.env = env
	return cont, nil
}

func (cont *CSRController) GetCA(caId string) (*x509.CA, error) {
	caCont, err := NewCA(cont.env)
	if err != nil {
		return nil, err
	}

	return caCont.GetCA(caId)
}

func (cont *CSRController) ResetCSRTags(csrId, tags string) error {
	logger.Debug("resetting CSR tags")
	logger.Tracef("received CSR id '%s' and tags '%s'", csrId, tags)

	orgIndex, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return err
	}

	if err := orgIndex.ClearCSRTags(csrId); err != nil {
		return err
	}

	err = orgIndex.AddCSRTags(csrId, ParseTags(tags))
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

func (cont *CSRController) GetCSR(id string) (*x509.CSR, error) {
	logger.Debug("getting CSR")
	logger.Tracef("received CSR id '%s'", id)

	logger.Debug("getting CSR from org")
	csrContainerJson, err := cont.env.api.GetPrivate(cont.env.controllers.org.OrgId(), id)
	if err != nil {
		return nil, err
	}

	logger.Debug("creating new container")
	csrContainer, err := document.NewContainer(csrContainerJson)
	if err != nil {
		return nil, err
	}

	logger.Debug("decrypting container")
	csrJson, err := cont.env.controllers.org.org.VerifyThenDecrypt(csrContainer)
	if err != nil {
		return nil, err
	}

	logger.Debug("loading CSR json")
	csr, err := x509.NewCSR(csrJson)
	if err != nil {
		return nil, err
	}

	logger.Trace("returning CSR")
	return csr, nil
}

func (cont *CSRController) SaveCSR(csr *x509.CSR) error {
	logger.Debug("saving CSR")
	logger.Tracef("received CSR with id '%s'", csr.Id)

	logger.Debug("encrypting CSR for org")
	csrContainer, err := cont.env.controllers.org.org.EncryptThenSignString(csr.Dump(), nil)
	if err != nil {
		return err
	}

	logger.Debug("saving encrypted csr")
	err = cont.env.api.SendPrivate(cont.env.controllers.org.org.Data.Body.Id, csr.Data.Body.Id, csrContainer.Dump())
	if err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}

func (cont *CSRController) AddCSRToOrgIndex(csr *x509.CSR, tags string) error {
	logger.Debug("adding CSR to org index")
	logger.Tracef("received CSR with id '%s' and tags '%s'", csr.Id(), tags)

	orgIndex, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return err
	}

	err = orgIndex.AddCSR(csr.Data.Body.Name, csr.Data.Body.Id)
	if err != nil {
		return err
	}

	err = orgIndex.AddCSRTags(csr.Data.Body.Id, ParseTags(tags))
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

func (cont *CSRController) New(params *CSRParams) (*x509.CSR, error) {
	logger.Debug("creating new CSR")
	logger.Tracef("received params: %s", params)

	if err := params.ValidateName(true); err != nil {
		return nil, err
	}

	if err := cont.env.LoadAdminEnv(); err != nil {
		return nil, err
	}

	// TODO - This should really be in a CSR function
	subject := pkix.Name{CommonName: *params.Name}

	if *params.DnLocality != "" {
		subject.Locality = []string{*params.DnLocality}
	}
	if *params.DnState != "" {
		subject.Province = []string{*params.DnState}
	}
	if *params.DnOrg != "" {
		subject.Organization = []string{*params.DnOrg}
	}
	if *params.DnOrgUnit != "" {
		subject.OrganizationalUnit = []string{*params.DnOrgUnit}
	}
	if *params.DnCountry != "" {
		subject.Country = []string{*params.DnCountry}
	}
	if *params.DnStreet != "" {
		subject.StreetAddress = []string{*params.DnStreet}
	}
	if *params.DnPostal != "" {
		subject.PostalCode = []string{*params.DnPostal}
	}

	logger.Debug("creating CSR struct")
	csr, err := x509.NewCSR(nil)
	if err != nil {
		return nil, err
	}

	csr.Data.Body.Id = x509.NewID()
	csr.Data.Body.Name = *params.Name

	if *params.CsrFile == "" && *params.KeyFile == "" {
		csr.Data.Body.KeyType = *params.KeyType
		logger.Debug("generating CSR and key")
		csr.Generate(&subject)
	} else {
		if *params.CsrFile == "" {
			return nil, fmt.Errorf("CSR PEM file must be provided if importing")
		}

		logger.Debugf("importing CSR from '%s'", *params.CsrFile)
		ok, err := fs.Exists(*params.CsrFile)
		if err != nil {
			return nil, err
		}

		if !ok {
			logger.Warnf("CSR file '%s' does not exist", *params.CsrFile)
			logger.Tracef("returning nil error")
			return nil, nil
		}

		logger.Debug("reading file")
		csrPem, err := fs.ReadFile(*params.CsrFile)
		if err != nil {
			return nil, err
		}

		logger.Debug("decoding CSR PEM")
		_, err = x509.PemDecodeX509CSR([]byte(csrPem))
		if err != nil {
			return nil, err
		}

		csr.Data.Body.CSR = csrPem

		if *params.KeyFile != "" {
			logger.Debugf("importing private key file from '%s'", *params.KeyFile)
			ok, err := fs.Exists(*params.KeyFile)
			if err != nil {
				return nil, err
			}

			if !ok {
				logger.Warnf("key file '%s' does not exist", *params.KeyFile)
				logger.Trace("returning nil error")
				return nil, nil
			}

			logger.Debugf("reading key file")
			keyPem, err := fs.ReadFile(*params.KeyFile)
			if err != nil {
				return nil, err
			}

			logger.Debug("decoding private key PEM")
			key, err := crypto.PemDecodePrivate([]byte(keyPem))
			if err != nil {
				return nil, err
			}

			keyType, err := crypto.GetKeyType(key)
			if err != nil {
				return nil, err
			}

			csr.Data.Body.KeyType = string(keyType)
			csr.Data.Body.PrivateKey = keyPem
		}
	}

	if *params.StandaloneFile == "" {
		err = cont.SaveCSR(csr)
		if err != nil {
			return nil, err
		}

		var tags string
		if *params.Tags == "NAME" {
			tags = *params.Name
		} else {
			tags = *params.Tags
		}

		err = cont.AddCSRToOrgIndex(csr, tags)
		if err != nil {
			return nil, err
		}
	}

	return csr, nil
}

func (cont *CSRController) List(params *CSRParams) ([]*x509.CSR, error) {
	logger.Debug("listing CSRs")
	logger.Tracef("received params: %s", params)

	if err := cont.env.LoadAdminEnv(); err != nil {
		return nil, err
	}

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return nil, err
	}

	csrs := make([]*x509.CSR, 0)
	for _, id := range index.GetCSRs() {
		csr, err := cont.GetCSR(id)
		if err != nil {
			return nil, err
		}
		csrs = append(csrs, csr)
	}

	logger.Trace("returning CSRs")
	return csrs, nil
}

func (cont *CSRController) Show(params *CSRParams) (*x509.CSR, error) {
	logger.Info("showing CSR")
	logger.Tracef("received params: %s", params)

	logger.Debug("Validating parameters")
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

	csrId, err := index.GetCSR(*params.Name)
	if err != nil {
		return nil, err
	}

	csr, err := cont.GetCSR(csrId)
	if err != nil {
		return nil, err
	}

	logger.Trace("returning CSR")
	return csr, nil
}

func (cont *CSRController) Sign(params *CSRParams) (*x509.Certificate, error) {
	logger.Debug("signing CSR")
	logger.Tracef("received params: %s", params)

	if err := params.ValidateName(true); err != nil {
		return nil, err
	}

	if err := cont.env.LoadAdminEnv(); err != nil {
		return nil, err
	}

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return nil, err
	}

	csrId, err := index.GetCSR(*params.Name)
	if err != nil {
		return nil, err
	}

	csr, err := cont.GetCSR(csrId)
	if err != nil {
		return nil, err
	}

	caId, err := index.GetCA(*params.Ca)
	if err != nil {
		return nil, err
	}

	caCont, err := NewCA(cont.env)
	if err != nil {
		return nil, err
	}

	ca, err := caCont.GetCA(caId)
	if err != nil {
		return nil, err
	}

	logger.Debug("signing CSR")
	cert, err := ca.Sign(csr, *params.KeepSubject)

	logger.Debug("setting certificate ID")
	cert.Data.Body.Id = x509.NewID()

	org := cont.env.controllers.org.org
	logger.Debug("encrypting certificate container for org")
	certContainer, err := org.EncryptThenSignString(cert.Dump(), nil)
	if err != nil {
		return nil, err
	}

	logger.Debug("sending encrypted container to org")
	if err := cont.env.api.SendPrivate(org.Data.Body.Id, cert.Data.Body.Id, certContainer.Dump()); err != nil {
		return nil, err
	}

	index.AddCert(cert.Data.Body.Name, cert.Data.Body.Id)
	index.AddCertTags(cert.Data.Body.Id, ParseTags(*params.Tags))

	if err := cont.env.controllers.org.SaveIndex(index); err != nil {
		return nil, err
	}

	logger.Debug("return certificate")
	return cert, nil
}

func (cont *CSRController) Update(params *CSRParams) error {
	logger.Debug("updating CSR")
	logger.Tracef("received params: %s", params)

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

	csrId, err := index.GetCSR(*params.Name)
	if err != nil {
		return err
	}

	csr, err := cont.GetCSR(csrId)
	if err != nil {
		return err
	}

	if *params.CsrFile != "" {
		ok, err := fs.Exists(*params.CsrFile)
		if err != nil {
			return err
		}
		if !ok {
			logger.Warnf("CSR file '%s' does not exist", *params.CsrFile)
			return nil
		}

		logger.Debugf("reading CSR file '%s'", *params.CsrFile)

		csrPem, err := fs.ReadFile(*params.CsrFile)
		if err != nil {
			return err
		}

		// TODO - better validation of pem
		logger.Debug("decoding CSR file PEM")
		_, err = x509.PemDecodeX509CSR([]byte(csrPem))
		if err != nil {
			return err
		}

		csr.Data.Body.CSR = csrPem
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

		logger.Debugf("reading key file '%s'", *params.KeyFile)

		keyPem, err := fs.ReadFile(*params.KeyFile)
		if err != nil {
			return err
		}

		logger.Debug("decoding key file PEM")
		key, err := crypto.PemDecodePrivate([]byte(keyPem))
		if err != nil {
			return err
		}

		keyType, err := crypto.GetKeyType(key)
		if err != nil {
			return err
		}

		csr.Data.Body.KeyType = string(keyType)
		csr.Data.Body.PrivateKey = keyPem
	}

	if *params.Tags != "" {
		cont.ResetCSRTags(csrId, *params.Tags)
	}

	err = cont.SaveCSR(csr)
	if err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}

func (cont *CSRController) Delete(params *CSRParams) error {
	logger.Debug("deleting CSR")
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

	csrId, err := index.GetCSR(*params.Name)
	if err != nil {
		return err
	}

	logger.Debug("removing CSR file")
	if err := cont.env.api.DeletePrivate(cont.env.controllers.org.OrgId(), csrId); err != nil {
		return err
	}

	if err := index.RemoveCSR(*params.Name); err != nil {
		return err
	}

	err = cont.env.controllers.org.SaveIndex(index)
	if err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}
