package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
)

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func main() {
	dat, err := ioutil.ReadFile("/tmp/dat")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(dat))
	block, _ := aes.NewCipher([]byte(createHash("pass")))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, dat, nil)
	fmt.Println(string(ciphertext))
	key := []byte(createHash("pass"))
	block2, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm2, err2 := cipher.NewGCM(block2)
	if err2 != nil {
		panic(err.Error())
	}
	nonceSize := gcm2.NonceSize()
	nonce2, ciphertext2 := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext2, err3 := gcm2.Open(nil, nonce2, ciphertext2, nil)
	if err3 != nil {
		panic(err.Error())
	}
	fmt.Println(string(plaintext2))
}
