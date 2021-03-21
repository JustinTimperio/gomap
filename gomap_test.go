package gomap_test

import (
	"fmt"
	"testing"

	"github.com/JustinTimperio/gomap"
)

func TestMain(m *testing.M) {
	fastscan := false
	proto := "tcp"
	stealth := true
	results, _ := gomap.ScanIP("192.168.1.120", proto, fastscan, stealth)
	// results, _ := gomap.ScanRange(fastscan, proto, fastscan, stealth)
	fmt.Println(results)
}
