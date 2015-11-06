package controller

import (
	"fmt"
)

type PairingKeyParams struct {
	Id            *string
	Tags          *string
	ConfirmDelete *string
	Private       *bool
}

func NewPairingKeyParams() *PairingKeyParams {
	return new(PairingKeyParams)
}

func (params *PairingKeyParams) ValidateID(required bool) error {
	if required && *params.Id == "" {
		return fmt.Errorf("id cannot be empty")
	}
	return nil
}

func (params *PairingKeyParams) ValidateTags(required bool) error          { return nil }
func (params *PairingKeyParams) ValidatePrivate(required bool) error       { return nil }
func (params *PairingKeyParams) ValidateConfirmDelete(required bool) error { return nil }
