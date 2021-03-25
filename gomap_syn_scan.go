package gomap

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net"
	"strconv"
	"strings"
)

func sendSyn(laddr string, raddr string, sport uint16, dport uint16) error {
	// Create TCP packet struct and header
	op := []tcpOption{
		{
			Kind:   2,
			Length: 4,
			Data:   []byte{0x05, 0xb4},
		},
		{
			Kind: 0,
		},
	}

	tcpH := tcpHeader{
		SrcPort:       sport,
		DstPort:       dport,
		SeqNum:        rand.Uint32(),
		AckNum:        0,
		Flags:         0x8002,
		Window:        8192,
		ChkSum:        0,
		UrgentPointer: 0,
	}

	// Connect to network interface to send packet
	conn, err := net.Dial("ip4:tcp", raddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Build dummy packet for checksum
	buff := new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, tcpH)

	for i := range op {
		binary.Write(buff, binary.BigEndian, op[i].Kind)
		binary.Write(buff, binary.BigEndian, op[i].Length)
		binary.Write(buff, binary.BigEndian, op[i].Data)
	}

	binary.Write(buff, binary.BigEndian, [6]byte{})
	data := buff.Bytes()
	checkSum := checkSum(data, ipstr2Bytes(laddr), ipstr2Bytes(raddr))
	tcpH.ChkSum = checkSum

	// Build final packet
	buff = new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, tcpH)

	for i := range op {
		binary.Write(buff, binary.BigEndian, op[i].Kind)
		binary.Write(buff, binary.BigEndian, op[i].Length)
		binary.Write(buff, binary.BigEndian, op[i].Data)
	}
	binary.Write(buff, binary.BigEndian, [6]byte{})

	// Send Packet
	conn.Write(buff.Bytes())
	return nil
}

func recvSynAck(laddr string, raddr string, port uint16, res chan<- bool) error {
	// Checks if the IP address is resolveable
	listenAddr, err := net.ResolveIPAddr("ip4", laddr)
	if err != nil {
		return err
	}

	// Connect to network interface to listen for packets
	conn, err := net.ListenIP("ip4:tcp", listenAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Read each packet looking for ack from raddr on packetport
	for {
		buff := make([]byte, 1024)
		_, addr, err := conn.ReadFrom(buff)
		if err != nil {
			continue
		}
		if addr.String() != raddr || buff[13] != 0x12 {
			continue
		}

		var packetport uint16
		binary.Read(bytes.NewReader(buff), binary.BigEndian, &packetport)
		if port != packetport {
			continue
		}

		res <- true
		return nil
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
