package encrypt

import (
	"crypto/md5"
	"encoding/hex"
)

// GoMd5 goMd5加密
func GoMd5(md5String string) string {
	ctx := md5.New()
	ctx.Write([]byte(md5String)) // 需要加密的字符串为 123456
	return hex.EncodeToString(ctx.Sum(nil))
}
