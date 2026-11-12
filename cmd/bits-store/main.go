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
	check := flag.Bool("check", false, "check the configuration file and exit: 0 if the service would take it")
	every := flag.Duration("reload-every", 5*time.Second, "how often to look for a changed configuration file; 0: never")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *health != "" {
		os.Exit(checkHealth(*health))
	}
	if *check {
		if err := server.CheckConfig(*config); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("ok")
		return
	}
	h, cfg, err := server.NewReloader(*config)
	if err != nil {
		log.Fatal(err)
	}
	if *every > 0 {
		go h.Watch(*every)
	}
	addr := cfg.Listen
	if *listen != "" {
		addr = *listen
	}
	if addr == "" {
		addr = ":8098"
	}
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second,
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
