package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/gophil/pcap"
	"os"
	"os/signal"
	"strconv"
	"time"
)

const (
	TYPE_IP  = 0x0800
	TYPE_ARP = 0x0806
	TYPE_IP6 = 0x86DD

	IP_ICMP = 1
	IP_INIP = 4
	IP_TCP  = 6
	IP_UDP  = 17
)

//命令行参数
var (
	device  = flag.String("i", "", "interface")      //设备名: en0,bond0
	ofile   = flag.String("d", "", "dump file path") //生成离线文件
	read    = flag.String("r", "", "read dump file") //生成离线文件
	snaplen = flag.Int("s", 65535, "snaplen")
	hexdump = flag.Bool("X", false, "hexdump")
	help    = flag.Bool("h", false, "help")
	count   = flag.String("c", "", "capture count of the dump line")
	timeout = flag.String("t", "", "timeout")
)

func main() {
	expr := ""

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"usage: %s \n [ -i interface ] \n [ -t timeout ] \n [ -c count ] \n [ -s snaplen ] \n [ -X hexdump ] \n [ -d dump file ] \n [ -r read file ] \n [ -h show usage] \n [ expression ] \n", os.Args[0])
		os.Exit(1)
	}

	flag.Parse()

	if len(flag.Args()) > 0 {
		expr = flag.Arg(0)
	}

	if *help {
		flag.Usage()
	}

	if *read != "" {
		src := *read
		f, err := os.Open(src)
		if err != nil {
			fmt.Printf("couldn't open %q: %v\n", src, err)
			return
		}
		defer f.Close()
		reader, err := pcap.NewReader(bufio.NewReader(f))
		if err != nil {
			fmt.Printf("couldn't create reader: %v\n", err)
			return
		}
		for {
			pkt := reader.Next()
			if pkt == nil {
				break
			}
			pkt.Decode()
			fmt.Println(pkt)
			if *hexdump {
				Hexdump(pkt)
			}
		}
		return
	}

	if *device == "" {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintln(os.Stderr, "tinydump: couldn't find any devices:", err)
		}
		if 0 == len(devs) {
			flag.Usage()
		}
		*device = devs[0].Name
	}

	//在线方式读取
	h, err := pcap.OpenLive(*device, int32(*snaplen), true, 500)
	if h == nil {
		fmt.Fprintf(os.Stderr, "tinydump:", err)
		return
	}
	defer h.Close()

	//设置过滤
	if expr != "" {
		fmt.Println("tinydump: setting filter to", expr)
		ferr := h.SetFilter(expr)
		if ferr != nil {
			fmt.Println("tinydump:", ferr)
		}
	}

	cs := *count
	lineCoint := 1
	useCount := false
	if cs != "" {
		useCount = true
		lineCoint, err = strconv.Atoi(cs)
		if err != nil {
			lineCoint = 1
		}
	}

	//生成离线分析文件
	if *ofile != "" {
		dumper, oerr := h.DumpOpen(ofile)
		signalNotify(h, dumper)
		if oerr != nil {
			fmt.Fprintln(os.Stderr, "tinydump: couldn't write to file:", oerr)
		}
		_, lerr := h.PcapLoop(lineCoint-1, dumper)
		if lerr != nil {
			fmt.Fprintln(os.Stderr, "tinydump: loop error:", lerr, h.Geterror())
		}
		defer h.PcapDumpClose(dumper)
		return
	}

	//超时处理
	ts := *timeout
	if ts != "" {
		t, err := strconv.Atoi(ts)
		if err == nil {
			time.AfterFunc(time.Second*time.Duration(t), func() {
				h.Close()
				os.Exit(1)
			})
		}
	}

	//监听事件消息输出
	for pkt, r := h.NextEx(); r >= 0; pkt, r = h.NextEx() {
		if r == 0 {
			// 超时, continue(100)
			continue
		}

		if useCount {
			lineCoint = lineCoint - 1
			if lineCoint < 0 {
				h.Close()
				os.Exit(1)
			}
		}

		pkt.Decode()
		fmt.Println(pkt)
		if *hexdump {
			Hexdump(pkt)
		}

	}
	fmt.Fprintln(os.Stderr, "tinydump:", h.Geterror())

}

//退出通知
func signalNotify(h *pcap.Pcap, dumper *pcap.PcapDumper) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			fmt.Fprintln(os.Stderr, "tinydump: received signal:", sig)
			if os.Interrupt == sig {
				//关闭退出
				h.PcapDumpClose(dumper)
				h.Close()
				os.Exit(1)
			}
		}
	}()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func Hexdump(pkt *pcap.Packet) {
	for i := 0; i < len(pkt.Data); i += 16 {
		Dumpline(uint32(i), pkt.Data[i:min(i+16, len(pkt.Data))])
	}
}

//行dump
func Dumpline(addr uint32, line []byte) {
	fmt.Printf("\t0x%04x: ", int32(addr))
	var i uint16
	for i = 0; i < 16 && i < uint16(len(line)); i++ {
		if i%2 == 0 {
			fmt.Print(" ")
		}
		fmt.Printf("%02x", line[i])
	}
	for j := i; j <= 16; j++ {
		if j%2 == 0 {
			fmt.Print(" ")
		}
		fmt.Print("  ")
	}
	fmt.Print("  ")
	for i = 0; i < 16 && i < uint16(len(line)); i++ {
		if line[i] >= 32 && line[i] <= 126 {
			fmt.Println("%c", line[i])
		} else {
			fmt.Print(".")
		}
	}
	fmt.Println()
}
