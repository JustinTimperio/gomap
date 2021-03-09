package gomap_test

import (
	"testing"

	"github.com/JustinTimperio/gomap"
)

func TestMain(m *testing.M) {
	fastscan := false
	results := gomap.ScanRange(fastscan)
	gomap.PrintRangeResults(results)

}
