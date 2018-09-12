package main

import (
	"Token/action"
	"commonPKG/common"
	"commonPKG/initPKG"
	"commonPKG/pb"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/go-xorm/xorm"
	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type server struct{}

func (s *server) GetToken(ctx context.Context, in *pb.Request) (*pb.Reply, error) {
	rp := &pb.Reply{}
	// token := ""
	status, msg, data := action.GetTK(in, Orm)

	rp.Replymsg = []byte(data)
	rb := &pb.ReplyBase{}
	rb.Status = status
	rb.Msg = msg
	rp.Rpbase = rb
	return rp, nil
}

func (s *server) ValidToken(ctx context.Context, in *pb.Request) (*pb.Reply, error) {
	rp := &pb.Reply{}
	token := string(in.Reqmessage)
	status, msg, data := action.ValidToken(token)
	rp.Replymsg = []byte(data)
	rb := &pb.ReplyBase{}
	rb.Status = status
	rb.Msg = msg
	rp.Rpbase = rb
	return rp, nil
}
func (s *server) RouteAuth(ctx context.Context, in *pb.Request) (*pb.Reply, error) {
	rp := &pb.Reply{}
	inMap := make(map[string]interface{})
	json.Unmarshal(in.Reqmessage, &inMap)
	status, msg := action.ApiRouteValid(inMap)
	rpbs := &pb.ReplyBase{}
	rpbs.Status, rpbs.Msg = status, msg
	rp.Rpbase = rpbs
	return rp, nil
}

var Orm = &xorm.Engine{}

func init() {
	var err error
	Orm, err = xorm.NewEngine("mysql", initPKG.Mysql_connStr)
	Orm.DB().SetConnMaxLifetime(time.Duration(20) * time.Second)
	fmt.Printf(initPKG.Mysql_connStr)
	if err != nil {
		common.LogsWithcontent("连接数据库" + initPKG.Mysql_connStr + "，连接失败，错误信息:" + err.Error())
	}
	Orm.ShowSQL(true)
	// Orm.Logger().SetLevel(core.LOG_DEBUG)
	// logWriter := &Oplog{}
	// logger := xorm.NewSimpleLogger(logWriter)

	// logger.ShowSQL(true)
	// // logger.SetLevel(core.LOG_INFO)
	// Orm.SetLogLevel(core.LOG_INFO)
	// Orm.SetLogger(logger)
	cacher := xorm.NewLRUCacher(xorm.NewMemoryStore(), 1000)
	Orm.SetDefaultCacher(cacher)
	// Orm.MapCacher(&models.AdminList{}, nil)
	// Orm.MapCacher(&models.AdminGroup{}, nil)
	go DBping() //keep dbconnect alive
}

type Oplog struct {
	log string
}

func (o *Oplog) Write(p []byte) (int, error) {
	o.log = string(p)
	fmt.Println(o.log)
	return len(p), nil
}
func DBping() {
	for {
		Orm.Ping()
		time.Sleep(time.Duration(20) * time.Second)
		// fmt.Println("ping")
	}
}
func main() {

	GrpcPort := initPKG.Config.Tokenport
	lis, err := net.Listen("tcp", GrpcPort)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterTokenHandleServer(s, &server{})

	// Register reflection service on gRPC server.
	reflection.Register(s)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

// func GetRoute() {
// 	siteMenu := new(md.SiteMenu)
// 	rows, _ := Orm.Rows(siteMenu)
// 	sm := []md.SiteMenu{}
// 	for rows.Next() {
// 		rows.Scan(siteMenu)
// 		sm = append(sm, *siteMenu)
// 	}
// 	PrintRoute(sm, "0")
// }

// var index = 1

// func PrintRoute(lis []md.SiteMenu, Pid string) {

// 	for _, tt := range lis {

// 		if Pid == tt.Pid {

// 			if len(tt.Url) > 0 {
// 				fmt.Println(" > > > " + tt.NameZh + "_" + tt.NameEn + "_route:" + tt.Url)
// 			} else {
// 				fmt.Println("-" + tt.NameZh + "_" + tt.NameEn)
// 			}
// 			PrintRoute(lis, tt.Id)
// 			index += 1
// 		}

// 	}

// }
