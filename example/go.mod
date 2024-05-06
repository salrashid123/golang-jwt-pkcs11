module main

go 1.20

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/salrashid123/golang-jwt-pkcs11 v0.0.0
)

require (
	github.com/ThalesIgnite/crypto11 v1.2.5 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
)

replace github.com/salrashid123/golang-jwt-pkcs11 => ../
