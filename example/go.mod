module main

go 1.23.6

toolchain go1.24.0

require (
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/salrashid123/golang-jwt-pkcs11 v0.0.0
)

require (
	github.com/ThalesGroup/crypto11 v1.4.1 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
)

replace github.com/salrashid123/golang-jwt-pkcs11 => ../
