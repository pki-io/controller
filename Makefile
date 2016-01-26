DIRS = admin ca certificate csr environment node org pairingkey ssh

default: get-deps test

get-deps:
	fdm

test:
	fdm test ./...

dev: clean get-deps
	test ! -d _vendor/pkg || rm -rf _vendor/pkg
	fdm
	fdm get github.com/stretchr/testify

lint:
	fdm --exec gometalinter ./...

clean:
	test ! -d _vendor || rm -rf _vendor/*
