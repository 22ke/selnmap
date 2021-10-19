package nmap

import (
	"bytes"
	"fmt"
	"os/exec"
)

type Nmap struct {
	//C config
	Command  []string
	Cmd      string
	Nmappath string
	Result   string
}

//func (n *Nmap) Start() {
//
//	for true {
//		ip := <- db.Newi
//		go n.Scan(ip.Ip, ip.Port)
//	}
////loop:
////	tk := time.NewTicker(10 * time.Second)
////	var ip string
////	var port string
////	num, v := db.Getallnewip()
////	if num != 0 {
////		for i := 0; i < num; i++ {
////			ip = v[i].Ip
////			port = v[i].Port
////			go n.Scan(ip, port)
////		}
////	}
////	<-tk.C
////	goto loop
//}
func (n *Nmap) Addcommand(s string){
	n.Command = append(n.Command, s)
}

func (n *Nmap) Scan(ip string, port string) error {
	var cmd *exec.Cmd
	var out, err bytes.Buffer

	n.Command = append(n.Command, ip)
	n.Command = append(n.Command, "-p")
	n.Command = append(n.Command, port)

	cmd = exec.Command(n.Nmappath, n.Command...)
	n.Command = nil
	n.Cmd = cmd.String()
	//fmt.Println("Nmap => ", cmd.Args)
	fmt.Println("Nmap:", cmd)

	cmd.Stdout = &out
	cmd.Stderr = &err

	e := cmd.Run()
	if e != nil {
		println(e.Error())
		if err.Len() > 0 {
			fmt.Printf("Nmap run err : %s\n", e.Error())
			println(err.String())
			return nil
		}
		return e
	}
	n.Result = out.String()
	//println(n.Result)
	println("")
	//db.SetDataFromXml(ip , port , n.Result)
	return nil
}
