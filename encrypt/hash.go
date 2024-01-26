package encrypt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/astaxie/beego/logs"
)

func GoHash256(str string) string {
	h := sha256.New()
	h.Write([]byte(str))
	sum := h.Sum(nil)

	//由于是十六进制表示，因此需要转换
	s := hex.EncodeToString(sum)
	return s
}

// HmacSha256 base64 输出
func HmacSha256(message string, secret string) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("错误HmacSha256密钥为空")
	}
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	sha := hex.EncodeToString(h.Sum(nil))
	logs.Debug(sha, "调试")
	return base64.StdEncoding.EncodeToString([]byte(sha)), nil

}

// HmacSha256NoBase  输出
func HmacSha256NoBase(message string, secret string) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("错误HmacSha256密钥为空")
	}
	iv := []byte(secret)
	h := hmac.New(sha256.New, iv)
	h.Write([]byte(message))
	sha := hex.EncodeToString(h.Sum(nil))
	logs.Debug(sha, "调试")
	return sha, nil
}
