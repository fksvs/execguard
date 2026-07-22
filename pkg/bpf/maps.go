package bpf

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func (g *Guard) TrackPID(pid uint32) error {
	val := uint8(1)
	return g.objs.TrackedPids.Put(pid, val)
}

func (g *Guard) SetEnforcing(enforce bool) error {
	key := uint32(0)
	val := uint8(0)

	if enforce {
		val = 1
	}

	return g.objs.GuardConfig.Put(key, val)
}

func (g *Guard) BackfillPID(pid uint32) error {
	if err := g.TrackPID(pid); err != nil {
		return fmt.Errorf("tracking pid %d: %w", pid, err)
	}

	return g.backfillChildren(pid)
}

func (g *Guard) backfillChildren(pid uint32) error {
	taskDir := fmt.Sprintf("/proc/%d/task", pid)
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil
	}

	seen := make(map[uint32]bool)
	for _, entry := range entries {
		tid := entry.Name()
		path := fmt.Sprintf("/proc/%d/task/%s/children", pid, tid)

		children, err := readChildren(path)
		if err != nil {
			continue
		}

		for _, child := range children {
			if seen[child] {
				continue
			}
			
			seen[child] = true
			
			if err := g.TrackPID(child); err != nil {
				return fmt.Errorf("tracking pid %d: %w", child, err)
			}
			
			if err := g.backfillChildren(child); err != nil {
				return err
			}
		}
	}

	return nil
}

func readChildren(path string) ([]uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	var pids []uint32
	sc := bufio.NewScanner(f)
	sc.Split(bufio.ScanWords)
	for sc.Scan() {
		tok := strings.TrimSpace(sc.Text())
		if tok == "" {
			continue
		}
		n, err := strconv.ParseUint(tok, 10, 32)
		if err != nil {
			continue
		}
		pids = append(pids, uint32(n))
	}

	return pids, sc.Err()
}
