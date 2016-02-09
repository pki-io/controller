package controller

import (
	"io/ioutil"
	"os"
	"path"
	"strings"
)

func setup() {
	tmp, err := ioutil.TempDir("", "pki.io-test")
	if err != nil {
		panic(err)
	}
	if err := os.Setenv("PKIIO_HOME", path.Join(tmp, "home")); err != nil {
		panic(err)
	}

	if err := os.Setenv("PKIIO_LOCAL", path.Join(tmp, "local")); err != nil {
		panic(err)
	}
}

func teardown() {
	var dir string
	home := os.Getenv("PKIIO_HOME")
	if home != "" {
		dir = home
		os.Unsetenv("PKIIO_HOME")
	} else {
		local := os.Getenv("PKIIO_LOCAL")
		if local != "" {
			dir = local
			os.Unsetenv("PKIIO_LOCAL")
		} else {
			panic("No PKIIO env variables set")
		}
	}

	parentDir := path.Dir(dir)
	if strings.Contains(parentDir, "pki.io-test") {
		if err := os.RemoveAll(parentDir); err != nil {
			panic(err)
		}
	} else {
		panic("Directory isn't a pki.io test directory")
	}

}
