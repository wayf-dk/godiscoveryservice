module github.com/wayf-dk/godiscoveryservice

go 1.22.0

require (
	github.com/mattn/go-sqlite3 v1.14.22
	github.com/wayf-dk/gosaml v0.0.0-20240226131603-95c38d32b4c5
	github.com/wayf-dk/goxml v0.0.0-20240226131044-6b837b25feb7
	x.config v0.0.0-00010101000000-000000000000
)

require (
	github.com/miekg/pkcs11 v1.1.2-0.20231115102856-9078ad6b9d4b // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/wayf-dk/go-libxml2 v0.0.0-20240227081341-0086175c2fd4 // indirect
	github.com/wayf-dk/goeleven v0.0.0-20230816115740-d287bc08e939 // indirect
	golang.org/x/crypto v0.20.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
)

replace (
	github.com/wayf-dk/go-libxml2 => ../go-libxml2
	github.com/wayf-dk/goeleven => ../goeleven
	github.com/wayf-dk/goxml => ../goxml
	github.com/wayf-dk/saml => ../gosaml
	x.config => ../hybrid-config
)
