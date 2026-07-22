package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
)

type Event struct {
	PID     uint32
	PPID    uint32
	Command [16]byte
	Path    [256]byte
	Denied  uint8
}

func (e *Event) CommandStr() string {
	return string(bytes.TrimRight(e.Command[:], "\x00"))
}

func (e *Event) PathStr() string {
	return string(bytes.TrimRight(e.Path[:], "\x00"))
}

func (g *Guard) ReadEvents(ctx context.Context, fn func(*Event)) error {
	rd, err := ringbuf.NewReader(g.objs.Events)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("reading ringbuf: %w", err)
		}

		var e Event
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &e); err != nil {
			continue
		}
		fn(&e)
	}
}
