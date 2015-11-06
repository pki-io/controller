package controller

import (
	"fmt"
)

// First-class types only
type CAParams struct {
	Name          *string
	Tags          *string
	CaExpiry      *int
	CertExpiry    *int
	KeyType       *string
	DnLocality    *string
	DnState       *string
	DnOrg         *string
	DnOrgUnit     *string
	DnCountry     *string
	DnStreet      *string
	DnPostal      *string
	ConfirmDelete *string
	Export        *string
	Private       *bool
	CertFile      *string
	KeyFile       *string
}

func NewCAParams() *CAParams {
	return new(CAParams)
}

// ThreatSpec TMv0.1 for CAParams.ValidateName
// Does name parameter validation for App:CAController

func (params *CAParams) ValidateName(required bool) error {
	if required && *params.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	return nil
}

func (params *CAParams) ValidateTags(required bool) error          { return nil }
func (params *CAParams) ValidateCAExpiry(required bool) error      { return nil }
func (params *CAParams) ValidateCertExpiry(required bool) error    { return nil }
func (params *CAParams) ValidateKeyType(required bool) error       { return nil }
func (params *CAParams) ValidateDnLocality(required bool) error    { return nil }
func (params *CAParams) ValidateDnState(required bool) error       { return nil }
func (params *CAParams) ValidateDnOrg(required bool) error         { return nil }
func (params *CAParams) ValidateDnOrgUnit(required bool) error     { return nil }
func (params *CAParams) ValidateDnCountry(required bool) error     { return nil }
func (params *CAParams) ValidateDnStreet(required bool) error      { return nil }
func (params *CAParams) ValidateDnPostal(required bool) error      { return nil }
func (params *CAParams) ValidateConfirmDelete(required bool) error { return nil }
func (params *CAParams) ValidateExport(required bool) error        { return nil }
func (params *CAParams) ValidatePrivate(required bool) error       { return nil }
func (params *CAParams) ValidateCertFile(required bool) error      { return nil }
func (params *CAParams) ValidateKeyFile(required bool) error       { return nil }
