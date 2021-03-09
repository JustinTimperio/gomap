package gomap_test

import (
	"testing"

	"github.com/JustinTimperio/gomap"
)

func TestMain(m *testing.M) {
	results := gomap.ScanRange()
	gomap.PrintRangeResults(results)

}
