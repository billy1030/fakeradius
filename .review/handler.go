// validateMessageAuthenticator validates the Message-Authenticator in a request packet.
// RFC-compliant implementation: Message-Authenticator = HMAC-MD5 only
func validateMessageAuthenticator(packet []byte, secret string) (valid bool, detectedAlgo string) {
	if !hasMessageAuthenticator(packet) {
		return true, ""
	}

	if len(packet) < 20 {
		return false, ""
	}

	length := uint16(packet[2])<<8 | uint16(packet[3])

	// Safety check: declared packet length must be valid
	if int(length) > len(packet) || length < 20 {
		return false, ""
	}

	// Extract received Message-Authenticator
	pos := 20
	var receivedMA []byte

	for pos < int(length) {
		if pos+2 > int(length) {
			break
		}

		attrType := packet[pos]
		attrLen := int(packet[pos+1])

		if attrLen < 2 || pos+attrLen > int(length) {
			break
		}

		if attrType == MessageAuthenticatorType && attrLen == 18 {
			receivedMA = make([]byte, 16)
			copy(receivedMA, packet[pos+2:pos+18])
			break
		}

		pos += attrLen
	}

	// If MA attribute is malformed, reject
	if receivedMA == nil {
		return false, ""
	}

	// Zero out MA attribute before HMAC calculation
	zeroMA := make([]byte, 16)
	attrsWithZeroedMA := replaceOrAddMA(packet[20:length], zeroMA)

	// RFC 2869 Section 5.14:
	// HMAC-MD5(Code + Identifier + Length + RequestAuth + Attributes-with-zeroed-MA)
	authData := make([]byte, 4+16+len(attrsWithZeroedMA))
	authData[0] = packet[0] // Code (Access-Request)
	authData[1] = packet[1] // Identifier
	binary.BigEndian.PutUint16(authData[2:4], length)
	copy(authData[4:20], packet[4:20]) // Request Authenticator
	copy(authData[20:], attrsWithZeroedMA)

	h := hmac.New(md5.New, []byte(secret))
	h.Write(authData)
	expectedMA := h.Sum(nil)

	if hmac.Equal(receivedMA, expectedMA) {
		return true, "md5"
	}

	return false, ""
}