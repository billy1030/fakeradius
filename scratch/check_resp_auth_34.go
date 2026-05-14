package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
)

func main() {
	secret := "testing123"
	
	// Code: 2, ID: 34 (0x22), Len: 69 (0x45)
	// Request Auth: 025b48ac4fa983cb662910bf040b188d
	// Attributes with zeroed MA:
	// 50 12 00000000000000000000000000000000
	// 12 19 41757468656e7469636174696f6e206163636570746564
	// 06 06 00000002
	
	dataHex := "02220045" + "025b48ac4fa983cb662910bf040b188d" + "501200000000000000000000000000000000" + "121941757468656e7469636174696f6e206163636570746564" + "060600000002" + hex.EncodeToString([]byte(secret))
	data, _ := hex.DecodeString(dataHex)
	
	hash := md5.Sum(data)
	fmt.Printf("Expected Response Auth: %s\n", hex.EncodeToString(hash[:]))
	fmt.Printf("Actual Response Auth:   db266fda9bb142e9245ff6de665d97cb\n")
}
