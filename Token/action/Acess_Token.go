package action

import (
	// "fmt"

	"commonPKG/initPKG"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// Header 消息头部
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// PayLoad 负载
type PayLoad struct {
	ID       string `json:"id"`
	GroupId  string `json:"group_id"`
	UserName string `json:"username"`
	RealName string `json:"realname"`
	Rules    string `json:"rules"`
	Expire   int    `json:"exp"`
}

// JWT 完整的本体
type JWT struct {
	Header    `json:"header"`
	PayLoad   `json:"payload"`
	Signature string `json:"signature"`
}

// Encode 将 json 转成符合 JWT 标准的字符串
func (jwt *JWT) Encode() (int32, string, string) {

	status := int32(502)
	msg := "加密失败"

	header, err := json.Marshal(jwt.Header)
	checkError(err)
	headerString := base64.StdEncoding.EncodeToString(header)
	payload, err := json.Marshal(jwt.PayLoad)
	payloadString := base64.StdEncoding.EncodeToString(payload)
	status, msg = checkError(err)

	format := headerString + "." + payloadString
	signature := getHmacCode(format)

	//先进行base64编码
	input := []byte(format + "." + signature)

	// 演示base64编码
	encodeString := base64.StdEncoding.EncodeToString(input)
	return status, msg, encodeString
}

func getHmacCode(s string) string {
	h := hmac.New(sha256.New, []byte(initPKG.SALT))
	h.Write([]byte(s))
	key := h.Sum(nil)
	return hex.EncodeToString(key)
}

// Decode 验证 jwt 签名是否正确,并将json内容解析出来
func (jwt *JWT) Decode(code string) bool {

	//先进行base64解码
	decodeBytes, err := base64.StdEncoding.DecodeString(code)
	if err != nil {
		// log.Fatalln(err)
		return false
	}

	arr := strings.Split(string(decodeBytes), ".")
	if len(arr) != 3 {
		return false
	}

	// 验证签名是否正确
	format := arr[0] + "." + arr[1]
	signature := getHmacCode(format)
	if signature != arr[2] {
		return false
	}

	header, err := base64.StdEncoding.DecodeString(arr[0])
	checkError(err)
	payload, err := base64.StdEncoding.DecodeString(arr[1])
	checkError(err)

	json.Unmarshal(header, &jwt.Header)
	json.Unmarshal(payload, &jwt.PayLoad)

	return true
}

func checkError(err error) (int32, string) {
	msg := ""
	status := int32(200)
	if err != nil {
		msg = err.Error()
		status = 100
		//panic(err)
	}
	return status, msg
}
