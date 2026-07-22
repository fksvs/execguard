package bpf

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const pinDir = "/sys/fs/bpf/execguard"
const configPinPath = pinDir + "/guard_config"

type Guard struct {
	objs  guardObjects
	links []link.Link
}

func IsRunning() bool {
	_, err := os.Stat(configPinPath)
	return err == nil
}

func SetEnforcingRunning(enforce bool) error {
	m, err := ebpf.LoadPinnedMap(configPinPath, nil)
	if err != nil {
		return fmt.Errorf("execguard is not running (no pinned config map at %s): %w", configPinPath, err)
	}
	defer m.Close()

	key := uint32(0)
	val := uint8(0)
	if enforce {
		val = 1
	}

	if err := m.Put(key, val); err != nil {
		return fmt.Errorf("updating guard_config: %w", err)
	}

	return nil
}

func Load() (*Guard, error) {
	if IsRunning() {
		return nil, fmt.Errorf("execguard is already loaded and attached (pin at %s); rerun with --enforce alone to change its mode", configPinPath)
	}

	if err := os.MkdirAll(pinDir, 0700); err != nil {
		return nil, fmt.Errorf("creating pin directory: %w", err)
	}

	g := &Guard{}

	if err := loadGuardObjects(&g.objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	if err := g.objs.GuardConfig.Pin(configPinPath); err != nil {
		g.objs.Close()
		return nil, fmt.Errorf("pinning guard_config map: %w", err)
	}

	forkLink, err := link.AttachTracing(link.TracingOptions{
		Program: g.objs.ExecguardFork,
	})
	if err != nil {
		g.close()
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

	if g.objs.GuardConfig != nil {
		_ = g.objs.GuardConfig.Unpin()
		_ = os.Remove(pinDir)
	}

	g.objs.Close()
}
