package gomap_test

import (
	"fmt"
	"testing"

	"github.com/JustinTimperio/gomap"
)

func TestMain(m *testing.M) {
	var (
		proto    = "tcp"
		fastscan = false
		stealth  = false
	)

	// results, err := gomap.ScanIP("192.168.1.120", proto, fastscan, stealth)
	results, err := gomap.ScanRange(proto, fastscan, stealth)

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(results)
	}
}
