// SPDX-License-Identifier: Apache-2.0

// Command bits-store is the site's store service (bits-services ADR 0004).
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
	"github.com/bitsorg/bits-store/internal/server"
)

var version = "dev"

func main() {
	config := flag.String("config", "/etc/bits-store/config.json", "configuration file")
	listen := flag.String("listen", "", "address to listen on (overrides the configuration)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	health := flag.String("health", "", "GET this /health URL, exit 0 if it answers 200 (a container's health check)")
	check := flag.Bool("check", false, "check the configuration file, and that each volume's keys list its bucket, and exit: 0 if the service would take it")
	every := flag.Duration("reload-every", 5*time.Second, "how often to look for a changed configuration file; 0: never")
	data := flag.String("data", "", "directory for the index (index.db); none: no index")
	gc := flag.Bool("gc", false, "plan a collection of the packages no verified common manifest lists, from the index in -data, and exit")
	gcGrace := flag.Duration("gc-grace", 30*24*time.Hour, "with -gc: packages younger than this stay")
	gcKeep := flag.Int("gc-keep-builds", 3, "with -gc: the newest this many builds of each package version stay; 0: no such rule")
	gcMax := flag.Float64("gc-max", 0.25, "with -gc: refuse when more than this share of an architecture's packages would go")
	gcRead := flag.Duration("gc-read", 30*24*time.Hour, "with -gc: packages read within this stay; 0: no such rule")
	gcReads := flag.Int("gc-reads", 10, "with -gc: packages read this many times stay for four times -gc-read; 0: no such rule")
	gcList := flag.Bool("gc-list", false, "with -gc: name each file that would go")
	gcOut := flag.String("gc-out", "", "with -gc: write the files that would go to this file, for review and -gc-apply")
	adminListen := flag.String("admin-listen", "", "also serve the admin API (/_admin/, admin keys' tokens only) on this address; none: off")
	gcApply := flag.String("gc-apply", "", "with -gc: delete the files this -gc-out file names that the plan, made now, still sweeps")
	flag.Parse()
	if flag.NArg() > 0 { // flags end at the first other word: the rest would be ignored
		fmt.Fprintf(os.Stderr, "not a flag: %q\n", flag.Arg(0))
		os.Exit(2)
	}
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *health != "" {
		os.Exit(checkHealth(*health))
	}
	if *check {
		if err := server.CheckConfig(*config, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("ok")
		return
	}
	flag.Visit(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "gc-") && !*gc {
			log.Fatalf("-%s is for -gc", f.Name) // never a second service beside the first
		}
	})
	if *gc {
		os.Exit(server.GC(*config, *data, server.GCOptions{Grace: *gcGrace, Max: *gcMax, Read: *gcRead,
			Reads: *gcReads, KeepBuilds: *gcKeep, List: *gcList, Out: *gcOut, Apply: *gcApply}, os.Stdout))
	}
	h, cfg, err := server.NewReloader(*config)
	if err != nil {
		log.Fatal(err)
	}
	if *data != "" {
		x, err := index.Open(filepath.Join(*data, "index.db"))
		if err != nil {
			log.Fatal(err)
		}
		h.UseIndex(x)
		go h.Verify()
		go h.FlushReads()
	}
	if *every > 0 {
		go h.Watch(*every)
	}
	if *adminListen != "" {
		if *data == "" {
			log.Fatal("-admin-listen needs -data: the admin API answers from the index")
		}
		ln, err := net.Listen("tcp", *adminListen) // before the store's: a bad address stops the start
		if err != nil {
			log.Fatal(err)
		}
		admin := &http.Server{Handler: http.HandlerFunc(h.ServeAdmin),
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: time.Minute,
			IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10}
		log.Printf("bits-store admin API on %s", *adminListen)
		go func() { log.Fatal(admin.Serve(ln)) }()
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
