package main

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"fmt"
)

func main() {
	secret := "testing123"
	dataHex := "020d003f7c43d26eaa6f6826310f97db979e64f9" + "501200000000000000000000000000000000" + "121941757468656e7469636174696f6e206163636570746564"
	data, _ := hex.DecodeString(dataHex)
	
	h := hmac.New(md5.New, []byte(secret))
	h.Write(data)
	expectedMA := h.Sum(nil)
	
	fmt.Printf("Expected Response MA: %s\n", hex.EncodeToString(expectedMA))
	fmt.Printf("Actual Response MA:   62ab6ce52683c8a05f7ca2e8b235e9c9\n")
}
