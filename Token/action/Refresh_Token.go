package action

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"
)

// PayLoad 负载
type PayLoadRefresh struct {
	Expire int `json:"exp"`
}

// JWT 完整的本体
type JWTRefresh struct {
	Header         `json:"header"`
	PayLoadRefresh `json:"payloadrefresh"`
	Signature      string `json:"signature"`
}

// Encode 将 json 转成符合 JWT 标准的字符串
func (jwt *JWTRefresh) EncodeRefresh() (int32, string, string) {

	status := int32(502)
	msg := "加密失败"

	header, err := json.Marshal(jwt.Header)
	checkError(err)
	headerString := base64.StdEncoding.EncodeToString(header)
	payload, err := json.Marshal(jwt.PayLoadRefresh)
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

// Decode 验证 jwt 签名是否正确,并将json内容解析出来
func (jwt *JWTRefresh) DecodeRefresh(code string) bool {

	//先进行base64解码
	decodeBytes, err := base64.StdEncoding.DecodeString(code)
	if err != nil {
		log.Fatalln(err)
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
	PayLoad, err := base64.StdEncoding.DecodeString(arr[1])
	checkError(err)

	json.Unmarshal(header, &jwt.Header)
	json.Unmarshal(PayLoad, &jwt.PayLoadRefresh)

	return true
}
