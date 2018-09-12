package action

import (
	"commonPKG/common"
	"commonPKG/redisClient"

	"strings"
)

func ApiRouteValid(inMap map[string]interface{}) (int32, string) {
	status := int32(403)
	msg := "没有权限，拒绝访问"

	routeRdsKey := "authroute:" + common.InterfaceToString(inMap["UserName"])

	res := redisClient.Redis.StringRead(routeRdsKey)
	// fmt.Printf(res)
	if strings.Contains(res, common.InterfaceToString(inMap["apiRoute"])) {
		status = 200
		msg = "授权成功"
	}
	return status, msg
}
