// ThreatSpec package controller
package controller

import (
	"crypto/x509/pkix"
	"fmt"
	"github.com/pki-io/core/crypto"
	"github.com/pki-io/core/document"
	"github.com/pki-io/core/fs"
	"github.com/pki-io/core/x509"
	"time"
)

type CertificateController struct {
	env *Environment
}

func NewCertificate(env *Environment) (*CertificateController, error) {
	cont := new(CertificateController)
	cont.env = env
	return cont, nil
}

func (cont *CertificateController) GetCA(caId string) (*x509.CA, error) {
	logger.Debug("getting CA")
	logger.Tracef("received CA id '%s'", caId)

	logger.Debug("creating new CA controller")
	caCont, err := NewCA(cont.env)
	if err != nil {
		return nil, err
	}

	logger.Debug("returning CA")
	return caCont.GetCA(caId)
}

func (cont *CertificateController) ResetCertTags(certId, tags string) error {
	logger.Debug("resetting certificate tags")
	logger.Tracef("received certificate id '%s' and tags '%s'", certId, tags)

	orgIndex, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return err
	}

	if err := orgIndex.ClearCertTags(certId); err != nil {
		return err
	}

	err = orgIndex.AddCertTags(certId, ParseTags(tags))
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

func (cont *CertificateController) GetCert(id string) (*x509.Certificate, error) {
	logger.Debug("getting certificate")
	logger.Tracef("received certificate id '%s'", id)

	logger.Debugf("getting private file '%s' from org", id)
	certContainerJson, err := cont.env.api.GetPrivate(cont.env.controllers.org.org.Data.Body.Id, id)
	if err != nil {
		return nil, err
	}

	logger.Debug("creating new container")
	certContainer, err := document.NewContainer(certContainerJson)
	if err != nil {
		return nil, err
	}

	logger.Debug("decrypting container")
	certJson, err := cont.env.controllers.org.org.VerifyThenDecrypt(certContainer)
	if err != nil {
		return nil, err
	}

	logger.Debug("loading certificate json")
	cert, err := x509.NewCertificate(certJson)
	if err != nil {
		return nil, err
	}

	logger.Trace("returning nil error")
	return cert, nil
}

func (cont *CertificateController) SaveCert(cert *x509.Certificate) error {
	logger.Debug("saving certificate")
	logger.Tracef("received certificate with id '%s'", cert.Id())

	logger.Debug("encrypting cert for org")
	certContainer, err := cont.env.controllers.org.org.EncryptThenSignString(cert.Dump(), nil)
	if err != nil {
		return err
	}

	logger.Debug("saving encrypted cert")
	err = cont.env.api.SendPrivate(cont.env.controllers.org.org.Data.Body.Id, cert.Data.Body.Id, certContainer.Dump())
	if err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}

func (cont *CertificateController) AddCertToOrgIndex(cert *x509.Certificate, tags string) error {
	logger.Debug("adding certificate to org index")
	logger.Tracef("received certificate with id '%s' and tags '%s'", cert.Id(), tags)

	orgIndex, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return err
	}

	err = orgIndex.AddCert(cert.Data.Body.Name, cert.Data.Body.Id)
	if err != nil {
		return err
	}

	err = orgIndex.AddCertTags(cert.Data.Body.Id, ParseTags(tags))
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

func (cont *CertificateController) New(params *CertificateParams) (*x509.Certificate, *x509.CA, error) {
	logger.Debug("creating new certificate")
	logger.Tracef("received params: %s", params)

	if err := params.ValidateName(true); err != nil {
		return nil, nil, err
	}

	if err := cont.env.LoadAdminEnv(); err != nil {
		return nil, nil, err
	}

	// TODO - This should really be in a certificate function
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

	logger.Debug("creating certificate struct")
	cert, err := x509.NewCertificate(nil)
	if err != nil {
		return nil, nil, err
	}

	cert.Data.Body.Name = *params.Name
	cert.Data.Body.Expiry = *params.Expiry

	var ca *x509.CA

	if *params.CertFile == "" && *params.KeyFile == "" {
		cert.Data.Body.KeyType = *params.KeyType
		logger.Debug("generating certificate and key")
		if *params.Ca == "" {
			if err := cert.Generate(nil, &subject); err != nil {
				return nil, nil, err
			}
		} else {
			index, err := cont.env.controllers.org.GetIndex()
			if err != nil {
				return nil, nil, err
			}

			caId, err := index.GetCA(*params.Ca)
			if err != nil {
				return nil, nil, err
			}

			ca, err = cont.GetCA(caId)
			if err != nil {
				return nil, nil, err
			}

			logger.Debugf("generating certificate and signing with CA '%s'", caId)
			if err := cert.Generate(ca, &subject); err != nil {
				return nil, nil, err
			}
		}
	} else {
		if *params.CertFile == "" {
			return nil, nil, fmt.Errorf("certificate PEM file must be provided if importing")
		}

		logger.Debugf("importing certificate from '%s'", *params.CertFile)
		ok, err := fs.Exists(*params.CertFile)
		if err != nil {
			return nil, nil, err
		}

		if !ok {
			logger.Warnf("certificate file '%s' does not exist", *params.CertFile)
			return nil, nil, nil
		}

		logger.Debug("reading certificate from file")
		certPem, err := fs.ReadFile(*params.CertFile)
		if err != nil {
			return nil, nil, err
		}

		logger.Debug("decoding certificate PEM")
		importCert, err := x509.PemDecodeX509Certificate([]byte(certPem))
		if err != nil {
			return nil, nil, err
		}

		cert.Data.Body.Id = x509.NewID()
		cert.Data.Body.Certificate = certPem
		certExpiry := int(importCert.NotAfter.Sub(importCert.NotBefore) / (time.Hour * 24))
		cert.Data.Body.Expiry = certExpiry

		if *params.KeyFile != "" {
			logger.Debugf("importing certificate privte key from '%s'", *params.KeyFile)
			ok, err := fs.Exists(*params.KeyFile)
			if err != nil {
				return nil, nil, err
			}

			if !ok {
				logger.Warnf("key file '%s' does not exist", *params.KeyFile)
				return nil, nil, nil
			}

			logger.Debug("reading private key file")
			keyPem, err := fs.ReadFile(*params.KeyFile)
			if err != nil {
				return nil, nil, err
			}

			logger.Debug("decoding private key PEM")
			key, err := crypto.PemDecodePrivate([]byte(keyPem))
			if err != nil {
				return nil, nil, err
			}

			logger.Debug("getting key type")
			keyType, err := crypto.GetKeyType(key)
			if err != nil {
				return nil, nil, err
			}

			cert.Data.Body.KeyType = string(keyType)
			cert.Data.Body.PrivateKey = keyPem
		}
	}

	if *params.StandaloneFile == "" {
		err = cont.SaveCert(cert)
		if err != nil {
			return nil, nil, err
		}

		var tags string
		if *params.Tags == "NAME" {
			tags = *params.Name
		} else {
			tags = *params.Tags
		}

		err = cont.AddCertToOrgIndex(cert, tags)
		if err != nil {
			return nil, nil, err
		}
	}

	logger.Trace("returning certificate")
	return cert, ca, nil
}

func (cont *CertificateController) List(params *CertificateParams) ([]*x509.Certificate, error) {
	logger.Debug("listing certificates")
	logger.Tracef("received params: %s", params)

	if err := cont.env.LoadAdminEnv(); err != nil {
		return nil, err
	}

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return nil, err
	}

	certs := make([]*x509.Certificate, 0)
	for _, id := range index.GetCerts() {
		cert, err := cont.GetCert(id)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}

	logger.Trace("returning certificates")
	return certs, nil
}

func (cont *CertificateController) Show(params *CertificateParams) (*x509.Certificate, error) {
	logger.Debug("showing certificate")
	logger.Tracef("received params: %s", params)

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

	certId, err := index.GetCert(*params.Name)
	if err != nil {
		return nil, err
	}

	cert, err := cont.GetCert(certId)
	if err != nil {
		return nil, err
	}

	logger.Debug("returning certificate")
	return cert, nil
}

func (cont *CertificateController) Update(params *CertificateParams) error {
	logger.Debug("updating certificate")
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

	certId, err := index.GetCert(*params.Name)
	if err != nil {
		return err
	}

	cert, err := cont.GetCert(certId)
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

		cert.Data.Body.Certificate = certPem
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

		logger.Debug("getting key type")
		keyType, err := crypto.GetKeyType(key)
		if err != nil {
			return err
		}

		cert.Data.Body.KeyType = string(keyType)
		cert.Data.Body.PrivateKey = keyPem
	}

	if *params.Tags != "" {
		cont.ResetCertTags(certId, *params.Tags)
	}

	err = cont.SaveCert(cert)
	if err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}

func (cont *CertificateController) Delete(params *CertificateParams) error {
	logger.Debug("deleting certificate")
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

	certId, err := index.GetCert(*params.Name)
	if err != nil {
		return err
	}

	logger.Debugf("removing certificate file '%s'", certId)
	if err := cont.env.api.DeletePrivate(cont.env.controllers.org.OrgId(), certId); err != nil {
		return err
	}

	if err := index.RemoveCert(*params.Name); err != nil {
		return err
	}

	err = cont.env.controllers.org.SaveIndex(index)
	if err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}
