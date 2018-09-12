package action

import (
	"commonPKG/common"
	md "commonPKG/models"
	"commonPKG/pb"
	"commonPKG/redisClient"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-xorm/xorm"
)

func GetTK(in *pb.Request, Orm *xorm.Engine) (int32, string, string) {

	status := int32(403)
	msg := "缺少参数"
	tokenStr := ""
	inMap := make(map[string]string)
	json.Unmarshal(in.Reqmessage, &inMap)
	if len(inMap["UserName"]) > 0 && len(inMap["PassWord"]) > 0 && len(inMap["GoogleCode"]) > 0 {
		if err := Orm.Ping(); err == nil {
			status = 401
			msg = "用户名不存在"
			user := &md.AdminList{}
			user.Username = inMap["UserName"]
			engine := Orm
			has, err := engine.Get(user)

			if err != nil {
				msg = "获取用户失败"
				common.LogsWithcontent("获取用户失败" + inMap["UserName"])
				return status, msg, tokenStr
			}
			if has {
				GoogleCode := common.SetGoogleAuth(30, 6)
				code, err := strconv.Atoi(inMap["GoogleCode"])
				if err != nil {
					msg = "验证码格式不对"
					return status, msg, tokenStr
				}
				statuss, msgs := GoogleCode.CheckGoogleCode(user.SecreKey, int64(code))
				statuss = 200 //正式记得注释
				if statuss != 200 {

					status = statuss
					msg = msgs
					return status, msg, ""
				}

				if user.Password != common.GetMd5(inMap["PassWord"]) {

					msg = "密码错误"
					return status, msg, tokenStr
				}

				if user.Status == 9 {
					msg = "帐号被锁定"
					return status, msg, tokenStr
				}
				if user.Status == -1 {
					msg = "帐号以删除"
					return status, msg, tokenStr
				}
				msg = "登录成功"
				//logstart
				log := &md.OperateLog{}
				log.Id = common.GetKeyId()
				log.Operator = inMap["UserName"]
				log.Username = inMap["UserName"]
				log.Ip = inMap["ClientIP"]
				log.Url = inMap["Host"]
				log.IsMobile, _ = strconv.Atoi(inMap["isMob"])
				log.OperatorType = 2
				log.Note = ("用户：" + inMap["UserName"] + "尝试登录，时间：" + time.Now().Format("2006-01-02 15:04") + "，结果：" + msg)
				log.Updatetime = time.Now()
				log.WebCode = user.WebCode
				go Orm.Insert(log)

				//logend

				userInfoKey := "UserInfo:" + user.Id
				userInfoMap := user.Struct2Map()

				redisClient.Redis.HashWrite(userInfoKey, userInfoMap, 30*60)

				//进行token签名
				jwt := &JWT{}
				header := Header{}
				payload := &PayLoad{}
				header.Alg = "HS256"
				header.Typ = "JWT"
				payload.ID = user.Id
				payload.GroupId = user.GroupId
				payload.UserName = user.Username
				payload.Rules = user.AuthRoutes

				d, _ := time.ParseDuration("15m")
				payload.Expire = int(time.Now().Add(d).Unix())
				jwt.Header = header
				jwt.PayLoad = *payload
				status, msg, tokenStr = jwt.Encode()
				WebCodeKey := "webcode:" + user.Username
				redisClient.Redis.KeyDel(WebCodeKey)

				if user.WebCode == "all" {
					mp["webcode"] = GetWebcode(Orm)
					redisClient.Redis.NXStringWrite(WebCodeKey, GetWebcode(Orm), 24*60*60)
				} else {
					mp["webcode"] = user.WebCode
					redisClient.Redis.NXStringWrite(WebCodeKey, user.WebCode, 24*60*60)
				}

				if status == 200 {
					jwtRef := &JWTRefresh{}
					jwtRef.Header = header
					day, _ := time.ParseDuration("24h")
					jwtRef.PayLoadRefresh = PayLoadRefresh{Expire: int(time.Now().Add(day).Unix())}
					refreshToken := ""
					status, msg, refreshToken = jwtRef.EncodeRefresh()
					if status == 200 {

						resKey := "RefreshToken:" + user.Id

						redisClient.Redis.KeyDel(resKey)
						redisClient.Redis.NXStringWrite(resKey, refreshToken, 24*60*60)
					}
					GetAuthRoute(user, Orm)
				}

			}
		} else {
			msg = err.Error()
		}
	}

	mp["token"] = tokenStr
	inter, _ := json.Marshal(mp)

	return status, msg, string(inter)
}

//如果可以，后期加上user级别qps控制
func ValidToken(token string) (int32, string, string) {
	status := int32(403)
	msg := "Token无效"
	vtmp := make(map[string]interface{})
	jwt := &JWT{}
	if jwt.Decode(token) {
		timeNow := int(time.Now().Unix())
		vtmp = common.Struct2Map(jwt.PayLoad, "")
		// vtmp["username"] = jwt.UserName
		// vtmp["realname"] = jwt.RealName
		// vtmp["rules"] = jwt.Rules
		// fmt.Println(jwt)
		if jwt.Expire > timeNow {

			status = int32(200)
			msg = ""
		} else {
			resKey := "RefreshToken:" + jwt.ID
			refreshToken := redisClient.Redis.StringRead(resKey)
			if refreshToken != "" {
				jwtRef := &JWTRefresh{}
				if jwtRef.DecodeRefresh(refreshToken) {
					if jwtRef.Expire > timeNow {
						dur, _ := time.ParseDuration("30m")
						jwt.Expire = int(time.Now().Add(dur).Unix())
						status, msg, token = jwt.Encode()
					}
				}
			}

		}
	}
	vtmp["token"] = token

	vtmpBts, _ := json.Marshal(vtmp)

	return status, msg, string(vtmpBts)
}

func GetAuthRoute(user *md.AdminList, Orm *xorm.Engine) {
	admingroup := &md.AdminGroup{}
	admingroup.Id = user.GroupId
	have, _ := Orm.Get(admingroup)
	rows, err := Orm.Where("isdelete=?", 0).Asc("sortid").Rows(&md.AuthRoute{})
	authroutestb := []md.AuthRoute{}
	authroutes := []md.AuthRoute{}
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	for rows.Next() {
		authroute := md.AuthRoute{}
		rows.Scan(&authroute)
		authroutestb = append(authroutestb, authroute)
	}

	authIntersection := make(map[string]int)

	if have {
		groupAuthroute := strings.Split(admingroup.AuthRoutes, "-")
		for _, route := range groupAuthroute {
			if strings.Contains(user.AuthRoutes, route) {
				authIntersection[route] = 1
			}
		}
	}
	apiRouteStr := ""
	for _, v := range authroutestb {
		if authIntersection[v.Id] == 1 {
			authroutes = append(authroutes, v)
		}
		//正式注释
		if true {
			authroutes = append(authroutes, v)
			apiRouteStr = fmt.Sprintf("%s %s %s", apiRouteStr, v.Apiroute, ",")
		}
	}

	if apiRouteStr != "" {
		routeRdsKey := "authroute:" + user.Username
		redisClient.Redis.KeyDel(routeRdsKey)
		redisClient.Redis.NXStringWrite(routeRdsKey, apiRouteStr, 24*60*60)
	}
	//fmt.Println(authroutes)
	mp["route"] = SortAUTHRoute(authroutes, "0")
	mp["btn"] = SortAUTHRouteBtn(authroutes)
}

var mp = make(map[string]interface{})

// var i = 0

func SortAUTHRoute(authroutes []md.AuthRoute, Id string) []interface{} {
	var mprs = []interface{}{}
	for _, v := range authroutes {
		if v.Pid == Id {

			mprss := common.Struct2Map(v, "Pid,Sortid,Isdelete,Apiroute")
			mprss["list"] = SortAUTHRoute(authroutes, v.Id)
			mprs = append(mprs, mprss)
			// mp[""]
		}
	}
	// fmt.Println(mprs)
	return mprs
}

func SortAUTHRouteBtn(authroutes []md.AuthRoute) []interface{} {
	var mprs = []interface{}{}
	for _, v := range authroutes {

		if v.Authtype == "btn" {
			mprss := make(map[string]interface{})
			mprss = common.Struct2Map(v, "Pid,Sortid,Isdelete,Apiroute")
			mprs = append(mprs, mprss)
		}

	}

	// fmt.Println(mprs)
	return mprs
}

func GetWebcode(Orm *xorm.Engine) string {
	webList := md.WebList{}
	rows, _ := Orm.Rows(&webList)
	webliststr := ""
	for rows.Next() {
		if err := rows.Scan(&webList); err == nil {
			webliststr = webliststr + webList.WebCode + ","
		}

	}
	return webliststr[0 : len(webliststr)-1]
}
