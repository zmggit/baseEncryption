package encrypt

import "encoding/base64"

// Base64StdEncode 加密
func Base64StdEncode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// Base64StdDecode 解密
func Base64StdDecode(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return []byte{}, err
	}
	return b, nil
}
