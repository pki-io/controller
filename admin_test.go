package controller

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewAdmin(t *testing.T) {
	setup()
	env := NewEnvironment()
	admin, err := NewAdmin(env)
	assert.NotNil(t, admin)
	assert.NoError(t, err)
	teardown()
}

func TestSetEnv(t *testing.T) {
	env := NewEnvironment()
	admin, _ := NewAdmin(env)
	env2 := NewEnvironment()
	err := admin.SetEnv(env2)
	assert.NoError(t, err)
}

func TestGetEnv(t *testing.T) {
	env := NewEnvironment()
	admin, _ := NewAdmin(env)
	env2, err := admin.GetEnv()
	assert.NotNil(t, env2)
	assert.NoError(t, err)
}

func TestLoadConfig(t *testing.T) {
	setup()
	env := NewEnvironment()
	env.LoadHomeFs()
	env.LoadLocalFs()
	admin, _ := NewAdmin(env)
	err := admin.LoadConfig()
	assert.NoError(t, err)
	teardown()
}

func TestSaveConfig(t *testing.T) {
	setup()
	env := NewEnvironment()
	env.LoadHomeFs()
	env.LoadLocalFs()
	admin, _ := NewAdmin(env)
	admin.LoadConfig()
	err := admin.SaveConfig()
	assert.NoError(t, err)
	teardown()
}

func TestCreateAdmin(t *testing.T) {
	env := NewEnvironment()
	admin, _ := NewAdmin(env)
	err := admin.CreateAdmin("test")
	assert.NoError(t, err)
}
