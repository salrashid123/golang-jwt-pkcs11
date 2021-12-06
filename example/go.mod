module main

go 1.17

require (
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/salrashid123/golang-jwt-pkcs11 v0.0.0
)

require (
	github.com/ThalesIgnite/crypto11 v1.2.5 // indirect
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
)

replace github.com/salrashid123/golang-jwt-pkcs11 => ../
