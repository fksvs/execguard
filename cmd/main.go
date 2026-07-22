package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fksvs/execguard/pkg/bpf"
)

func main() {
	pid := flag.Uint("target-pid", 0, "target PID to guard")
	enforce := flag.Bool("enforce", false, "block exec attempts")
	flag.Parse()

	if *pid == 0 {
		if bpf.IsRunning() {
			if err := bpf.SetEnforcingRunning(*enforce); err != nil {
				fmt.Fprintf(os.Stderr, "execguard: %v\n", err)
				os.Exit(1)
			}

			mode := "monitor"
			if *enforce {
				mode = "enforce"
			}
			fmt.Printf("execguard: switched running instance to [%s] mode\n", mode)
			return
		}

		fmt.Fprintln(os.Stderr, "usage: execguard --target-pid <pid> [--enforce]")
		os.Exit(1)
	}

	guard, err := bpf.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "execguard: load: %v\n", err)
		os.Exit(1)
	}
	defer guard.Close()

	if err := guard.SetEnforcing(*enforce); err != nil {
		fmt.Fprintf(os.Stderr, "execguard: set enforce: %v\n", err)
		os.Exit(1)
	}

	/* backfill the tracked_pids map */
	if err := guard.BackfillPID(uint32(*pid)); err != nil {
		fmt.Fprintf(os.Stderr, "execguard: backfill: %v\n", err)
		os.Exit(1)
	}

	mode := "monitor"
	if *enforce {
		mode = "enforce"
	}
	fmt.Printf("execguard: watching pid %d [%s]\n", *pid, mode)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := guard.ReadEvents(ctx, func(e *bpf.Event) {
		action := "ALLOW"
		if e.Denied != 0 {
			action = "DENY "
		}
		fmt.Printf("[%s] pid=%-6d ppid=%-6d comm=%-16s path=%s\n",
			action, e.PID, e.PPID, e.CommandStr(), e.PathStr())
	}); err != nil {
		fmt.Fprintf(os.Stderr, "execguard: event loop: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("execguard: done")
}
