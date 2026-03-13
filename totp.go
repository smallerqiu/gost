package gost

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

func VerifyOTP(secret, pass string) bool {
	now := time.Now().UTC().Unix()
	skew := config.Auth.DynamicSkew
	period := config.Auth.DynamicPeriod

	for i := -skew; i <= skew; i++ {

		t := (now / period) + int64(i)

		code := generateTOTP(secret, t)

		if code == pass {
			return true
		}
	}
	return false
}

func generateTOTP(secret string, counter int64) string {
	key := []byte(secret)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	h := hmac.New(sha1.New, key)
	h.Write(buf[:])
	hash := h.Sum(nil)
	offset := hash[len(hash)-1] & 0x0f
	truncated :=
		(binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", truncated)
}

func generateSecret(ip, user string) string {
	src := ip + ":" + user + ":" + config.Auth.Secret
	hash := sha256.Sum256([]byte(src))
	return hex.EncodeToString(hash[:])
}

func verifyOTP(secret, pass string) (bool, int64) {
	now := time.Now().UTC().Unix()
	skew := config.Auth.DynamicSkew
	period := config.Auth.DynamicPeriod

	for i := -skew; i <= skew; i++ {
		counter := (now / period) + int64(i)
		code := generateTOTP(secret, counter)
		if code == pass {
			return true, counter
		}
	}
	return false, 0
}

func GeneratePassword(ip, user string) string {
	src := ip + user + config.Auth.Secret
	hash := sha256.New()
	hash.Write([]byte(src))
	hashedSrc := hash.Sum(nil)
	hashedSrcHex := hex.EncodeToString(hashedSrc)
	return hashedSrcHex
}
