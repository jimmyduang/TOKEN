package hook

import (
	"Token/common"
	"Token/model"
	"encoding/json"
	"fmt"

	"strings"
)

var Aes *common.AES

var hook_encode_url = ""
var hook_decode_url = ""

func init() {
	common.Config.getConf()
	hook_encode_url = common.Config.Encodeurl
	hook_decode_url = common.Config.Decodeurl
}

/**
* 通过接口加密
 */
func EncodeString(encode string) string {
	h_res := ""
	web_list := model.WebListByCodeRedis("tbet")
	Aes = common.SetAES(web_list["web_key"], "", "")
	h_res = Aes.AesEncryptString(encode)
	return h_res
	//	h_res := ""
	//	h_param := fmt.Sprintf("str=%s", encode)
	//	h_http_res, h_http_status := cm.HttpPostBody(hook_encode_url, h_param, false)
	//	if h_http_status != 200 {
	//		h_http_res, h_http_status = cm.HttpPostBody(hook_encode_url, h_param, false)
	//	}
	//	var h_json map[string]string
	//	err := json.Unmarshal([]byte(h_http_res), &h_json)
	//	if err == nil {
	//		h_res = h_json["encode"]
	//	}
	return h_res
}

/**
* 通过接口解密
 */
func DecodeString(decode string) string {
	h_res := ""
	decode = strings.Replace(decode, "+", "%2B", -1)
	h_param := fmt.Sprintf("str=%s", decode)
	h_http_res, h_http_status := cm.HttpPostBody(hook_decode_url, h_param, false)
	if h_http_status != 200 {
		h_http_res, h_http_status = cm.HttpPostBody(hook_decode_url, h_param, false)
	}
	var h_json map[string]string
	err := json.Unmarshal([]byte(h_http_res), &h_json)
	if err == nil {
		h_res = h_json["decode"]
	}

	if len(h_res) < 1 {
		web_list := model.WebListByCodeRedis("tbet")
		Aes = cm.SetAES(web_list["web_key"], "", "")
		h_res = Aes.AesDecryptString(decode)
	}
	return h_res
}

/**
* 通过接口解密
 */
func WebDecodeString(web_code, decode string) string {
	h_res := ""
	decode = strings.Replace(decode, "+", "%2B", -1)
	h_param := fmt.Sprintf("str=%s", decode)
	h_http_res, h_http_status := cm.HttpPostBody(hook_decode_url, h_param, false)
	if h_http_status != 200 {
		h_http_res, h_http_status = cm.HttpPostBody(hook_decode_url, h_param, false)
	}
	var h_json map[string]string
	err := json.Unmarshal([]byte(h_http_res), &h_json)
	if err == nil {
		h_res = h_json["decode"]
	}

	if len(h_res) < 1 {
		web_list := model.WebListByCodeRedis(web_code)
		Aes = cm.SetAES(web_list["web_key"], "", "")
		h_res = Aes.AesDecryptString(decode)
	}
	return h_res
}
