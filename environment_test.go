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
	assert.NoError(t, err)
	assert.NotEqual(t, env.fs.local, "")
}

func TestLoadHomeFs(t *testing.T) {
	env := NewEnvironment()
	err := env.LoadHomeFs()
	assert.NoError(t, err)
	assert.NotEqual(t, env.fs.home, "")
}

func TestLoadAPI(t *testing.T) {
	env := NewEnvironment()
	env.LoadLocalFs()
	err := env.LoadAPI()
	assert.NoError(t, err)
}
