package main

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"fmt"
)

func main() {
	secret := "testing123"
	
	// Construct the data to be hashed for MA
	// Code: 2, ID: 10, Len: 63 (0x3f)
	// Resp Auth: ca6c23fa6da3e00125479415f635748a
	// Attributes with zeroed MA:
	// 50 12 00000000000000000000000000000000
	// 12 19 41757468656e7469636174696f6e206163636570746564
	
	dataHex := "020a003fca6c23fa6da3e00125479415f635748a" + "501200000000000000000000000000000000" + "121941757468656e7469636174696f6e206163636570746564"
	data, _ := hex.DecodeString(dataHex)
	
	h := hmac.New(md5.New, []byte(secret))
	h.Write(data)
	expectedMA := h.Sum(nil)
	
	fmt.Printf("Expected Response MA: %s\n", hex.EncodeToString(expectedMA))
	fmt.Printf("Actual Response MA:   5670661c312639d5a718e17a736bcac3\n")
}
