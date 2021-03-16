package gomap_test

import (
	"fmt"
	"testing"

	"github.com/JustinTimperio/gomap"
)

func TestMain(m *testing.M) {
	fastscan := true
	results, _ := gomap.ScanRange(fastscan)
	// results, _ := gomap.ScanIP("127.0.0.1", fastscan)

	fmt.Println(results)
}
