package controller

import (
	"fmt"
)

type CertificateParams struct {
	Name           *string
	Tags           *string
	StandaloneFile *string
	Expiry         *int
	Ca             *string
	KeyType        *string
	DnLocality     *string
	DnState        *string
	DnOrg          *string
	DnOrgUnit      *string
	DnCountry      *string
	DnStreet       *string
	DnPostal       *string
	ConfirmDelete  *string
	Export         *string
	Private        *bool
	CertFile       *string
	KeyFile        *string
}

func NewCertificateParams() *CertificateParams {
	return new(CertificateParams)
}

func (params *CertificateParams) ValidateName(required bool) error {
	if required && *params.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	return nil
}

func (params *CertificateParams) ValidateStandalone(required bool) error    { return nil }
func (params *CertificateParams) ValidateTags(required bool) error          { return nil }
func (params *CertificateParams) ValidateExpiry(required bool) error        { return nil }
func (params *CertificateParams) ValidateKeyType(required bool) error       { return nil }
func (params *CertificateParams) ValidateDnLocality(required bool) error    { return nil }
func (params *CertificateParams) ValidateDnState(required bool) error       { return nil }
func (params *CertificateParams) ValidateDnOrg(required bool) error         { return nil }
func (params *CertificateParams) ValidateDnOrgUnit(required bool) error     { return nil }
func (params *CertificateParams) ValidateDnCountry(required bool) error     { return nil }
func (params *CertificateParams) ValidateDnStreet(required bool) error      { return nil }
func (params *CertificateParams) ValidateDnPostal(required bool) error      { return nil }
func (params *CertificateParams) ValidateConfirmDelete(required bool) error { return nil }
func (params *CertificateParams) ValidateExport(required bool) error        { return nil }
func (params *CertificateParams) ValidatePrivate(required bool) error       { return nil }
func (params *CertificateParams) ValidateCertFile(required bool) error      { return nil }
func (params *CertificateParams) ValidateKeyFile(required bool) error       { return nil }
