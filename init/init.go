package init

import(
	"os"
//	"os/exec"
	"fmt"
//	"path/filepath"
//	"database/sql"

	"../subscription"
	"../node"
)


//判断目录是否存在返回布尔类型
func path_exists(path string)bool{
    _,err := os.Stat(path)
    if err!=nil{
        if os.IsExist(err){
            return true
        }else{
            return false
        }
    }else{
        return true
    }
}

func Init(config_path,sql_db_path string){
    //判断目录是否存在 不存在则创建
    if !path_exists(config_path){
        err := os.Mkdir(config_path, os.ModePerm)
        if err!=nil{
            fmt.Println(err)
        }
	}
	
	if !path_exists(sql_db_path){
		subscription.Subscription_link_init(sql_db_path)
		subscription.Init_config_db(sql_db_path)
		node.Ssr_server_node_init(sql_db_path)
	}
}