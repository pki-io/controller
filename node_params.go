package controller

import (
	"fmt"
)

type NodeParams struct {
	Name          *string
	Tags          *string
	PairingId     *string
	PairingKey    *string
	ConfirmDelete *string
	Export        *string
	Private       *bool
}

func NewNodeParams() *NodeParams {
	return new(NodeParams)
}

func (params *NodeParams) ValidateName(required bool) error {
	if required && *params.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	return nil
}

func (params *NodeParams) ValidateTags(required bool) error          { return nil }
func (params *NodeParams) ValidateConfirmDelete(required bool) error { return nil }
func (params *NodeParams) ValidateExport(required bool) error        { return nil }
func (params *NodeParams) ValidatePrivate(required bool) error       { return nil }
func (params *NodeParams) ValidatePairingId(required bool) error     { return nil }
func (params *NodeParams) ValidatePairingKey(required bool) error    { return nil }
