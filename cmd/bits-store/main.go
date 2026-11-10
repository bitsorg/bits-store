// SPDX-License-Identifier: Apache-2.0

// Command bits-store is the site's store service (bits-services ADR 0004).
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/bitsorg/bits-store/internal/server"
)

var version = "dev"

func main() {
	config := flag.String("config", "/etc/bits-store/config.json", "configuration file")
	listen := flag.String("listen", "", "address to listen on (overrides the configuration)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	cfg, err := server.LoadConfig(*config)
	if err != nil {
		log.Fatal(err)
	}
	s, err := server.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	addr := cfg.Listen
	if *listen != "" {
		addr = *listen
	}
	if addr == "" {
		addr = ":8080"
	}
	srv := &http.Server{Addr: addr, Handler: s, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute,
		MaxHeaderBytes: 16 << 10}
	log.Printf("bits-store %s listening on %s", version, addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
