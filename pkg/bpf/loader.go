package bpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type Guard struct {
	objs  guardObjects
	links []link.Link
}

func Load() (*Guard, error) {
	g := &Guard{}

	if err := loadGuardObjects(&g.objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	forkLink, err := link.AttachTracing(link.TracingOptions{
		Program: g.objs.ExecguardFork,
	})
	if err != nil {
		g.objs.Close()
		return nil, fmt.Errorf("attaching fork tracepoint: %w", err)
	}
	g.links = append(g.links, forkLink)

	exitLink, err := link.AttachTracing(link.TracingOptions{
		Program: g.objs.ExecguardExit,
	})
	if err != nil {
		g.close()
		return nil, fmt.Errorf("attaching exit tracepoint: %w", err)
	}
	g.links = append(g.links, exitLink)

	lsmLink, err := link.AttachLSM(link.LSMOptions{
		Program: g.objs.ExecguardSec,
	})
	if err != nil {
		g.close()
		return nil, fmt.Errorf("attaching LSM hook: %w", err)
	}
	g.links = append(g.links, lsmLink)

	return g, nil
}

func (g *Guard) Close() {
	g.close()
}

func (g *Guard) close() {
	for _, l := range g.links {
		l.Close()
	}
	g.links = nil
	g.objs.Close()
}
