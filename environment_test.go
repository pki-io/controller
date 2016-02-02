package controller

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewEnvironment(t *testing.T) {
	env := NewEnvironment()
	assert.NotNil(t, env)
}

func TestLoadLocalFs(t *testing.T) {
	env := NewEnvironment()
	err := env.LoadLocalFs()
	assert.Nil(t, err)
}
