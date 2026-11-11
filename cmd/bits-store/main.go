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
	health := flag.String("health", "", "GET this /health URL, exit 0 if it answers 200 (a container's health check)")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *health != "" {
		os.Exit(checkHealth(*health))
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
		addr = ":8098"
	}
	srv := &http.Server{Addr: addr, Handler: s, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, // a promote extends its own
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 16 << 10}
	log.Printf("bits-store %s listening on %s", version, addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

// checkHealth is the probe for an image without a shell or curl.
func checkHealth(url string) int {
	c := &http.Client{Timeout: 3 * time.Second}
	r, err := c.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, r.Status)
		return 1
	}
	return 0
}
