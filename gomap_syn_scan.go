package gomap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

//TCPHeader test
type TCPHeader struct {
	SrcPort       uint16
	DstPort       uint16
	SeqNum        uint32
	AckNum        uint32
	Flags         uint16
	Window        uint16
	ChkSum        uint16
	UrgentPointer uint16
}

//TCPOption test
type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

type scanResult struct {
	Port   uint16
	Opened bool
}

type scanJob struct {
	Laddr string
	Raddr string
	SPort uint16
	DPort uint16
	Stop  uint8
}

var stopFlag = make(chan uint8, 1)

func SynTest() {
	laddr := "192.168.1.100"
	raddr := "192.168.1.120"
	minPort, maxPort := 1, 5000
	fmt.Println("Scanning", raddr, "from ports", minPort, "to", maxPort)

	rate := time.Second / 400
	throttle := time.Tick(rate)
	jobs := make(chan *scanJob, 65536)
	results := make(chan *scanResult, 5000)

	for w := 0; w < 10; w++ {
		go worker(w, jobs, throttle, results)
	}

	go func() {
		for i := 0; i < 10; i++ {
			recvSynAck(laddr, raddr, results)
		}
	}()

	go func() {
		for j := minPort; j < maxPort+1; j++ {
			s := scanJob{
				Laddr: laddr,
				Raddr: raddr,
				SPort: uint16(random(10000, 65535)),
				DPort: uint16(j + 1),
			}
			jobs <- &s
		}
		jobs <- &scanJob{Stop: 1}
	}()

	for {
		select {
		case res := <-results:
			fmt.Println(res)
		case <-stopFlag:
			time.Sleep(time.Second * 1)
			os.Exit(0)
		}
	}
}

func worker(id int, jobs <-chan *scanJob, th <-chan time.Time, results chan<- *scanResult) {
	for j := range jobs {
		if j.Stop != 1 {
			sendSyn(j.Laddr, j.Raddr, j.SPort, j.DPort)
		} else {
			stopFlag <- j.Stop
		}
		<-th
	}
}

func sendSyn(laddr, raddr string, sport, dport uint16) {
	conn, err := net.Dial("ip4:tcp", raddr)
	printError(err)
	defer conn.Close()
	op := []TCPOption{
		TCPOption{
			Kind:   2,
			Length: 4,
			Data:   []byte{0x05, 0xb4},
		},
		TCPOption{
			Kind: 0,
		},
	}

	tcpH := TCPHeader{
		SrcPort:       sport,
		DstPort:       dport,
		SeqNum:        rand.Uint32(),
		AckNum:        0,
		Flags:         0x8002,
		Window:        8192,
		ChkSum:        0,
		UrgentPointer: 0,
	}

	buff := new(bytes.Buffer)

	err = binary.Write(buff, binary.BigEndian, tcpH)
	printError(err)
	for i := range op {
		binary.Write(buff, binary.BigEndian, op[i].Kind)
		binary.Write(buff, binary.BigEndian, op[i].Length)
		binary.Write(buff, binary.BigEndian, op[i].Data)
	}

	binary.Write(buff, binary.BigEndian, [6]byte{})

	data := buff.Bytes()
	checkSum := checkSum(data, ipstr2Bytes(laddr), ipstr2Bytes(raddr))
	tcpH.ChkSum = checkSum

	buff = new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, tcpH)
	for i := range op {
		binary.Write(buff, binary.BigEndian, op[i].Kind)
		binary.Write(buff, binary.BigEndian, op[i].Length)
		binary.Write(buff, binary.BigEndian, op[i].Data)
	}
	binary.Write(buff, binary.BigEndian, [6]byte{})
	data = buff.Bytes()

	_, err = conn.Write(data)
	printError(err)
}

func recvSynAck(laddr, raddr string, res chan<- *scanResult) error {
	listenAddr, err := net.ResolveIPAddr("ip4", laddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenIP("ip4:tcp", listenAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	for {
		buff := make([]byte, 1024)
		_, addr, err := conn.ReadFrom(buff)
		if err != nil {
			continue
		}

		if addr.String() != raddr || buff[13] != 0x12 {
			continue
		}

		var port uint16
		binary.Read(bytes.NewReader(buff), binary.BigEndian, &port)

		res <- &scanResult{
			Port:   port,
			Opened: true,
		}
	}
}

func checkSum(data []byte, src, dst [4]byte) uint16 {
	pseudoHeader := []byte{
		src[0], src[1], src[2], src[3],
		dst[0], dst[1], dst[2], dst[3],
		0,
		6,
		0,
		byte(len(data)),
	}

	totalLength := len(pseudoHeader) + len(data)
	if totalLength%2 != 0 {
		totalLength++
	}

	d := make([]byte, 0, totalLength)
	d = append(d, pseudoHeader...)
	d = append(d, data...)

	var sum uint32
	for i := 0; i < len(d)-1; i += 2 {
		sum += uint32(uint16(d[i])<<8 | uint16(d[i+1]))
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return ^uint16(sum)

}

func printError(err error) {
	if err != nil {
		log.Println(err)
	}
}

func ipstr2Bytes(addr string) [4]byte {
	s := strings.Split(addr, ".")
	b0, _ := strconv.Atoi(s[0])
	b1, _ := strconv.Atoi(s[1])
	b2, _ := strconv.Atoi(s[2])
	b3, _ := strconv.Atoi(s[3])
	return [4]byte{byte(b0), byte(b1), byte(b2), byte(b3)}
}

func random(min, max int) int {
	return rand.Intn(max-min) + min
}
