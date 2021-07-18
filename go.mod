module github.com/wayf-dk/godiscoveryservice

go 1.16

require (
	github.com/mattn/go-sqlite3 v1.14.8
	github.com/wayf-dk/gosaml v0.0.0-20210625075105-0384b2997a7c
	github.com/wayf-dk/goxml v0.0.0-20201218125345-b1a8c71da4f0
	x.config v0.0.0-00010101000000-000000000000
)

replace (
	github.com/wayf-dk/go-libxml2 => ../go-libxml2
	github.com/wayf-dk/goxml => ../goxml
	x.config => ../hybrid-config
)
