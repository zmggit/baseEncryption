/*
*

	@authoer: lss
	@date: 2021/2/1
	@note:

*
*/
package encrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/astaxie/beego/logs"
	"os"
)

// RSA加密
// plainText 要加密的数据
// path 公钥匙文件地址
func RSAEncrypt(plainText []byte, path string) string {
	//打开文件
	file, err := os.Open(path)
	if err != nil {
		logs.Error(err)
		return ""
	}
	defer file.Close()
	//读取文件的内容
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem解码
	block, _ := pem.Decode(buf)
	//x509解码

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		logs.Error(err)
		return ""
	}
	//类型断言
	publicKey := publicKeyInterface.(*rsa.PublicKey)
	//对明文进行加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		logs.Error(err)
		return ""
	}
	//返回密文
	return base64.StdEncoding.EncodeToString(cipherText)
}

// RSA解密
// cipherText 需要解密的byte数据
// path 私钥文件路径
func RSADecrypt(enstr string, path string) (string, error) {
	var resString string
	data, err := base64.StdEncoding.DecodeString(enstr)
	if err != nil {
		return resString, err
	}
	//打开文件
	file, err := os.Open(path)
	if err != nil {
		return resString, err
	}
	defer file.Close()
	//获取文件内容
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem解码
	block, _ := pem.Decode(buf)
	//X509解码
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return resString, err
	}
	//对密文进行解密
	plainText, _ := rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
	//返回明文
	return string(plainText), err
}
