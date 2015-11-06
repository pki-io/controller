package controller

import (
	"fmt"
)

type AdminParams struct {
	Name          *string
	InviteId      *string
	InviteKey     *string
	ConfirmDelete *string
}

func NewAdminParams() *AdminParams {
	return new(AdminParams)
}

func (params *AdminParams) ValidateName(required bool) error {
	if required && *params.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	return nil
}

func (params *AdminParams) ValidateInviteId(required bool) error  { return nil }
func (params *AdminParams) ValidateInviteKey(required bool) error { return nil }
