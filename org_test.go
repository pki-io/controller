package controller

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewOrg(t *testing.T) {
	env := NewEnvironment()
	org, err := NewOrg(env)
	assert.NotNil(t, org)
	assert.NoError(t, err)
}
