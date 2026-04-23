package gost

import (
	"testing"
	"time"
)

func TestQiuTea(t *testing.T) {

	var secret = "abcdefg"

	startSec := 0
	passkey := GenerateShortOTP(secret)
	println("password:", passkey)
	for {
		println("password:", passkey)
		startSec++
		time.Sleep(1 * time.Second)

		valid := VerifyShortOTP(secret, passkey, 40)
		println("times:", startSec)
		if !valid {
			println(" false")
			break
		}
	}
}

func TestQiuTea2(t *testing.T) {

	secret := generateSecret("192.168.1.1", "user")

	for {
		passkey := GenerateShortOTP(secret)

		println("secret: ", secret)
		println("password:", passkey)
		time.Sleep(1 * time.Second)
	}
}

func TestQiuTea3(t *testing.T) {

	password := "8b0775013ae1e3714914c9e6"
	secret := "c00cd5a1f706b614c7e4882ff7ea6d535971e685b8d75741b446f05d28db3447"
	startSec := 0
	for {
		println("password:", password)
		startSec++
		time.Sleep(1 * time.Second)

		valid := VerifyShortOTP(secret, password, 20)
		println("times:", startSec)
		if !valid {
			println(" false")
			break
		}
	}
}
