package controller

import (
	"fmt"
)

type OrgParams struct {
	Org           *string
	Admin         *string
	ConfirmDelete *string
	Private       *bool
}

func NewOrgParams() *OrgParams {
	return new(OrgParams)
}

func (params *OrgParams) ValidateOrg() error {
	if *params.Org == "" {
		return fmt.Errorf("invalid org: Cannot be empty")
	}
	return nil
}

func (params *OrgParams) ValidateAdmin() error {
	if *params.Admin == "" {
		return fmt.Errorf("invalid admin: Cannot be empty")
	}
	return nil
}
