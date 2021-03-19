package gomap_test

import (
	"fmt"
	"testing"

	"github.com/JustinTimperio/gomap"
)

func TestMain(m *testing.M) {
	fastscan := true
	proto := "tcp"
	stealth := false
	// results, _ := gomap.ScanRange(fastscan)
	results, _ := gomap.ScanIP("127.0.0.1", proto, fastscan, stealth)
	fmt.Println(results)
	// fmt.Println(gomap.InterfaceAddress("wlp2s0"))
}
