package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
)

func main() {
	secret := "testing123"
	authHex := "025b48ac4fa983cb662910bf040b188d"
	passHex := "f77ae613d92b5ec36a6fec1b30df2d67"
	
	auth, _ := hex.DecodeString(authHex)
	pass, _ := hex.DecodeString(passHex)
	
	h := md5.New()
	h.Write([]byte(secret))
	h.Write(auth)
	b1 := h.Sum(nil)
	
	result := make([]byte, 16)
	for i := 0; i < 16; i++ {
		result[i] = pass[i] ^ b1[i]
	}
	
	fmt.Printf("Decrypted Password: %s (hex: %s)\n", string(result), hex.EncodeToString(result))
}
