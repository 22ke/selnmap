package nmap

import (
	"github.com/beevik/etree"
	"strings"
)

//数据库结构
type Ipassent struct {
	ID           int
	Ip           string `gorm:"not null"`
	Port         string `gorm:"not null"`
	Protocal     string     //tcp
	Servname     string     //ssh
	Servproduct  string     //openssh
	Serversion   string     //7.4
	Servextra    string     //protocol2.0
	Msgid        string     //http-server-header,http-title
	Msgoutput    string     //nginx/1.15.3,web
	Osname       string     //linux2.3-4.9
	Servmethod   string     //probed
	State        string     //up
	Addr         string     //00:0C:29:F1:37:49
	Addrtype     string     //mac
	Vendor       string     //VMware
 	Reason       string     //arp-response
	Cms          string
	Url          string     //http://1.1.1.1
	Title        string     //登录
	Firsttime    string `gorm:"type:timestamp;not null;default:now()"`
	Lasttime     string `gorm:"type:timestamp;not null;default:now()"`
}

func SetDataFromXml(ip string , port string,info string) Ipassent {


	dd :=etree.NewDocument()
	if err := dd.ReadFromString(info);err!=nil{
		println("etree error: " , err.Error())
	}
	ROOT := dd.SelectElement("nmaprun")
	//println("etree  tag : " , ROOT.Tag)

	HOST   := ROOT.SelectElement("host")

	STATUS := HOST.SelectElement("status")
    state  := STATUS.SelectAttrValue("state" , "")
	reason := STATUS.SelectAttrValue("reason" , "")
	var add ,addrtype,vendor []string
	for _ , ADDR := range HOST.SelectElements("address"){
		add      = append(add , ADDR.SelectAttrValue("addr" , ""))
		addrtype = append(addrtype,ADDR.SelectAttrValue("addrtype",""))
		vendor   = append(vendor,ADDR.SelectAttrValue("vendor",""))
		//println("add: " , add , " addtype: ", addrtype ," vendor: ", vendor)
	}

	PORTS        := HOST.SelectElement("ports")
	PORT         := PORTS.SelectElement("port")
	protocol     := PORT.SelectAttrValue("protocol" , "")       //tcp

	SERVICE      := PORT.SelectElement("service")
	servName     := SERVICE.SelectAttrValue("name" , "")       //ssh
	servProduct  := SERVICE.SelectAttrValue("product" , "")    //OpenSSH
	servversion  := SERVICE.SelectAttrValue("version" , "")    //7.4
	servextrainfo:= SERVICE.SelectAttrValue("extrainfo" , "")   //protocol 2.0
	servmethod   := SERVICE.SelectAttrValue("method" , "")      //probed

	var scriptid []string
	var scriptoutput []string
	for _ , script   := range PORT.SelectElements("script"){
		scriptid      = append(scriptid,script.SelectAttrValue("id" , ""))
		scriptoutput  = append(scriptoutput , script.SelectAttrValue("output" , ""))
	}

	OS := HOST.SelectElement("os")
	OSMATCH := OS.SelectElement("osmatch")
	osname := OSMATCH.SelectAttrValue("name" , "no osname")              //Linux 3.2 - 4.9
	id := strings.Join(scriptid , ",")
	output:=strings.Join(scriptoutput , ",")

	ipinfo := Ipassent{
		Ip:              ip,
		Port:            port,
		Protocal:        protocol,
		Servname:        servName,
		Servproduct:     servProduct,
		Serversion:      servversion,
		Servextra:       servextrainfo,
		Servmethod:      servmethod,
		State:           state,
		Reason:          reason,
		Msgid:           id,
		Msgoutput:       output,
		Osname:          osname,
		Addr:            strings.Join(add     ,","),
		Addrtype:        strings.Join(addrtype,","),
		Vendor:          strings.Join(vendor  ,","),
	}
	return ipinfo

}
