package controller

import (
	"fmt"
)

type CSRParams struct {
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
	KeepSubject    *bool
	CsrFile        *string
	KeyFile        *string
}

func NewCSRParams() *CSRParams {
	return new(CSRParams)
}

func (params *CSRParams) ValidateName(required bool) error {
	if required && *params.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	return nil
}

func (params *CSRParams) ValidateStandalone(required bool) error    { return nil }
func (params *CSRParams) ValidateTags(required bool) error          { return nil }
func (params *CSRParams) ValidateExpiry(required bool) error        { return nil }
func (params *CSRParams) ValidateKeyType(required bool) error       { return nil }
func (params *CSRParams) ValidateDnLocality(required bool) error    { return nil }
func (params *CSRParams) ValidateDnState(required bool) error       { return nil }
func (params *CSRParams) ValidateDnOrg(required bool) error         { return nil }
func (params *CSRParams) ValidateDnOrgUnit(required bool) error     { return nil }
func (params *CSRParams) ValidateDnCountry(required bool) error     { return nil }
func (params *CSRParams) ValidateDnStreet(required bool) error      { return nil }
func (params *CSRParams) ValidateDnPostal(required bool) error      { return nil }
func (params *CSRParams) ValidateConfirmDelete(required bool) error { return nil }
func (params *CSRParams) ValidateExport(required bool) error        { return nil }
func (params *CSRParams) ValidatePrivate(required bool) error       { return nil }
func (params *CSRParams) ValidateKeepSubject(required bool) error   { return nil }
func (params *CSRParams) ValidateCSRFile(required bool) error       { return nil }
func (params *CSRParams) ValidateKeyFile(required bool) error       { return nil }
