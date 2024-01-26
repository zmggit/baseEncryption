package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"strings"
)

// PasswordEncrypt 兼容php的password_encrypt 方式
func PasswordEncrypt(rawData string) (string, error) {
	iv := []byte("1610964531628002")
	key := []byte("exwryYCJd8pvGSM6XLWKjY1IW6OKbTNX")
	res, err := Encrypt([]byte(rawData), key, iv)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(res)), nil
}

func Encrypt(rawData, keyB []byte, iv []byte) (string, error) {
	key := make([]byte, 32)
	copy(key[:], keyB)
	data, err := AesCBCEncrypt(rawData, key, iv)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// Dncrypt 解密
func Dncrypt(rawData string, keyB []byte, iv []byte) (string, error) {
	key := make([]byte, 32)
	copy(key[:], keyB)
	data, err := base64.StdEncoding.DecodeString(rawData)
	if err != nil {
		return "", err
	}
	dnData, err := AesCBCDncrypt(data, key, iv)
	if err != nil {
		return "", err
	}
	return string(dnData), nil
}

// AesCBCEncrypt aes加密，填充秘钥key的16位，24,32分别对应AES-128, AES-192, or AES-256.
func AesCBCEncrypt(rawData, key []byte, iv []byte) ([]byte, error) {
	//logs.Debug(rawData, "调试")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//填充原文
	blockSize := block.BlockSize()
	rawData = PKCS7Padding(rawData, blockSize)
	//初始向量IV必须是唯一，但不需要保密
	cipherText := make([]byte, len(rawData))
	//block大小和初始向量大小一定要一致
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, rawData)

	return cipherText, nil
}

// AesCBCDncrypt aes解密密，填充秘钥key的16位，24,32分别对应AES-128, AES-192, or AES-256.
func AesCBCDncrypt(encryptData, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if len(encryptData) < blockSize {
		return nil, errors.New("ciphertext too short")
	}
	//encryptData = encryptData[blockSize:]
	// CBC mode always works in whole blocks.
	if len(encryptData)%blockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(encryptData, encryptData)
	//解填充
	encryptData = PKCS7UnPadding(encryptData)
	cutTrailingSpaces := []byte(strings.TrimSpace(string(encryptData)))

	return cutTrailingSpaces, nil
}

// PKCS7Padding 使用PKCS7进行填充，IOS也是7
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	res := append(ciphertext, padtext...)
	//logs.Error(res)
	return res
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	res := origData[:(length - unpadding)]
	return res
}
