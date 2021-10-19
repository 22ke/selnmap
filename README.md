# usenamp
go项目中使用nmap
其他地方看的轮子不太符合自己的用法，重新写了一个，
输出扫描值可以是结果字符串自己处理，也可以用内置的输出结果，详见test_main.go

```
package main

import (
	"fmt"
	"github.com/22ke/selnmap/nmap"
)

func main() {
	n := &nmap.Nmap{
		Nmappath: "lib\\nmap.exe",
	}
	n.Addcommand("-A")
	n.Addcommand("-oX")
	n.Addcommand("-")

	n.Scan("172.31.61.202", "22")
	ip := nmap.SetDataFromXml("1.1.1.1", "22", n.Result)
	println(n.Cmd)
	println("-------------------------")
	fmt.Printf("%s , %s , %s , %s , %s , %s , %s , %s , %s , %s , %s , %s , %s, %s , %s , %s\r\n\r\n", ip.Ip, ip.Port, ip.Protocal, ip.Servname,
		ip.Servproduct, ip.Serversion, ip.Servextra, ip.Msgid, ip.Msgoutput, ip.Osname, ip.Servmethod, ip.State, ip.Reason, ip.Addr, ip.Addrtype, ip.Vendor)
	println("=========================")
	fmt.Printf("%v", ip)
}
```
