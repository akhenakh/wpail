// Command devlistener is a tiny throwaway web server for exercising wpail
// the way a developer would: launch it with `task listener` (which runs
// `go run .` so wpail sees a temp build) and point wpail at its port:
//
//	task listener            # listens on :18081
//	task listener -- -port 9000
//	task run -- -v 18081     # inspect it with wpail
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
)

func main() {
	port := flag.Int("port", 18081, "TCP port to listen on")
	flag.Parse()

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("bind %s: %v", addr, err)
	}
	fmt.Printf("devlistener (pid %d) listening on http://%s — Ctrl+C to stop\n", os.Getpid(), addr)
	log.Fatal(http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from devlistener, pid %d\n", os.Getpid())
	})))
}
