// buildResponsePacket creates a fully RFC-compliant RADIUS response packet.
//
// Fixes:
// 1. Response Authenticator includes shared secret
// 2. Temporary Response Authenticator includes shared secret
// 3. Proper response Message-Authenticator circular dependency handling
func buildResponsePacket(
	requestPacket []byte,
	secret string,
	code byte,
	identifier byte,
	replyMessage string,
) []byte {

	// Request Authenticator from Access-Request
	requestAuth := make([]byte, 16)
	if len(requestPacket) >= 20 {
		copy(requestAuth, requestPacket[4:20])
	}

	// -----------------------------
	// Step 1: Build normal attributes
	// -----------------------------
	attributes := []byte{}

	if replyMessage != "" {
		attributes = append(
			attributes,
			buildAttribute(ReplyMessageType, []byte(replyMessage))...,
		)
	}

	hasRequestMA := hasMessageAuthenticator(requestPacket)

	// ------------------------------------------------------------
	// Step 2: If request had MA, response should also include MA
	// ------------------------------------------------------------
	if hasRequestMA {
		zeroMA := make([]byte, 16)
		maAttrZeroed := buildAttribute(MessageAuthenticatorType, zeroMA)

		// Temporary attributes with zeroed MA
		tempAttrs := append([]byte{}, attributes...)
		tempAttrs = append(tempAttrs, maAttrZeroed...)

		totalLen := uint16(20 + len(tempAttrs))

		// ------------------------------------------------------------
		// Step 2A:
		// Temporary Response Authenticator
		//
		// MD5(Code + ID + Length + RequestAuth + Attrs + Secret)
		// ------------------------------------------------------------
		tempAuthData := make([]byte, 4+16+len(tempAttrs)+len(secret))

		tempAuthData[0] = code
		tempAuthData[1] = identifier
		binary.BigEndian.PutUint16(tempAuthData[2:4], totalLen)

		copy(tempAuthData[4:20], requestAuth)
		copy(tempAuthData[20:20+len(tempAttrs)], tempAttrs)
		copy(tempAuthData[20+len(tempAttrs):], []byte(secret))

		tempRespAuth := md5.Sum(tempAuthData)

		// ------------------------------------------------------------
		// Step 2B:
		// Real Message-Authenticator
		//
		// HMAC-MD5(Code + ID + Length + ResponseAuth + Attrs-with-zeroed-MA)
		// ------------------------------------------------------------
		realMA := calculateMessageAuthenticator(
			code,
			identifier,
			totalLen,
			tempRespAuth[:],
			secret,
			tempAttrs,
		)

		// Final attributes = original attrs + real MA
		attributes = append([]byte{}, attributes...)
		attributes = append(
			attributes,
			buildAttribute(MessageAuthenticatorType, realMA)...,
		)
	}

	// ------------------------------------
	// Step 3: Final Response Authenticator
	// ------------------------------------
	totalLen := uint16(20 + len(attributes))

	packet := make([]byte, totalLen)

	packet[0] = code
	packet[1] = identifier
	binary.BigEndian.PutUint16(packet[2:4], totalLen)

	// RFC 2865:
	// Response Authenticator =
	// MD5(Code + ID + Length + RequestAuth + Attributes + Secret)
	finalAuthData := make([]byte, 4+16+len(attributes)+len(secret))

	finalAuthData[0] = code
	finalAuthData[1] = identifier
	binary.BigEndian.PutUint16(finalAuthData[2:4], totalLen)

	copy(finalAuthData[4:20], requestAuth)
	copy(finalAuthData[20:20+len(attributes)], attributes)
	copy(finalAuthData[20+len(attributes):], []byte(secret))

	finalRespAuth := md5.Sum(finalAuthData)

	copy(packet[4:20], finalRespAuth[:])
	copy(packet[20:], attributes)

	return packet
}