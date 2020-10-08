package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/getlantern/quicwrapper"
)

func main() {
	ctx, _ := context.WithTimeout(context.Background(), 2*time.Second)
	err := quicwrapper.ScanQUIC(ctx, os.Args[1])
	if err != nil {
		fmt.Printf("error: %v\n", err)
	} else {
		fmt.Printf("connected!\n")
	}
}
