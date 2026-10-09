// guest-mux is a transport adapter. It only opens the fixed QEMU guestfwd
// address; the parent process performs all HTTP and outbound network work.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const magic = "QUICKSAND-PROXY-MUX/1\n"
const maxFrame = 65536
const maxChannels = 64
const (
	openFrame  byte = 1
	dataFrame  byte = 2
	endFrame   byte = 3
	resetFrame byte = 4
)

type frame struct {
	kind byte
	data []byte
}
type channel struct {
	conn  net.Conn
	inbox chan frame
	done  chan struct{}
	once  sync.Once
}

func (ch *channel) close() { ch.once.Do(func() { close(ch.done); ch.conn.Close() }) }

type mux struct {
	conn     net.Conn
	writeMu  sync.Mutex
	mu       sync.Mutex
	channels map[uint32]*channel
	next     uint32
}

func (m *mux) send(kind byte, id uint32, payload []byte) error {
	header := make([]byte, 9)
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], id)
	binary.BigEndian.PutUint32(header[5:], uint32(len(payload)))
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	m.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := m.conn.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := m.conn.Write(payload)
		return err
	}
	return nil
}
func (m *mux) remove(id uint32, ch *channel) {
	m.mu.Lock()
	delete(m.channels, id)
	m.mu.Unlock()
	ch.close()
}
func (m *mux) serve(c net.Conn) {
	m.mu.Lock()
	if len(m.channels) >= maxChannels || m.next == ^uint32(0) {
		m.mu.Unlock()
		c.Close()
		return
	}
	m.next++
	id := m.next
	ch := &channel{conn: c, inbox: make(chan frame, 8), done: make(chan struct{})}
	m.channels[id] = ch
	m.mu.Unlock()
	defer m.remove(id, ch)
	if m.send(openFrame, id, nil) != nil {
		return
	}
	downstreamDone := make(chan struct{})
	go func() {
		defer close(downstreamDone)
		for {
			select {
			case f := <-ch.inbox:
				if f.kind == dataFrame {
					c.SetWriteDeadline(time.Now().Add(30 * time.Second))
					if _, err := c.Write(f.data); err != nil {
						ch.close()
						return
					}
				} else if f.kind == endFrame {
					if tcp, ok := c.(*net.TCPConn); ok {
						tcp.CloseWrite()
					}
					return
				} else {
					ch.close()
					return
				}
			case <-ch.done:
				return
			}
		}
	}()
	buf := make([]byte, maxFrame)
	for {
		n, err := c.Read(buf)
		if n > 0 && m.send(dataFrame, id, buf[:n]) != nil {
			return
		}
		if err != nil {
			if err == io.EOF {
				if m.send(endFrame, id, nil) == nil {
					// A client may close its write side while still awaiting a
					// response. Keep the channel alive until the host ends it.
					select {
					case <-downstreamDone:
					case <-ch.done:
					}
				}
			} else {
				m.send(resetFrame, id, nil)
			}
			return
		}
	}
}
func (m *mux) receive() error {
	for {
		var header [9]byte
		if _, err := io.ReadFull(m.conn, header[:]); err != nil {
			return err
		}
		kind, id, size := header[0], binary.BigEndian.Uint32(header[1:]), binary.BigEndian.Uint32(header[5:])
		if id == 0 || size > maxFrame || (kind != dataFrame && kind != endFrame && kind != resetFrame) || (kind != dataFrame && size != 0) {
			return fmt.Errorf("invalid frame")
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(m.conn, payload); err != nil {
			return err
		}
		m.mu.Lock()
		ch := m.channels[id]
		m.mu.Unlock()
		if ch != nil {
			select {
			case ch.inbox <- frame{kind, payload}:
			case <-ch.done:
			}
		}
	}
}
func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: guest-mux localhost-listen guestfwd-address")
	}
	listener, err := net.Listen("tcp", os.Args[1])
	if err != nil {
		return err
	}
	defer listener.Close()
	c, err := net.DialTimeout("tcp", os.Args[2], 10*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err = io.WriteString(c, magic); err != nil {
		return err
	}
	header := make([]byte, len(magic))
	if _, err = io.ReadFull(c, header); err != nil {
		return err
	}
	if string(header) != magic {
		return fmt.Errorf("bad handshake")
	}
	c.SetDeadline(time.Time{})
	m := &mux{conn: c, channels: make(map[uint32]*channel)}
	go func() {
		err := m.receive()
		fmt.Fprintln(os.Stderr, err)
		listener.Close()
		m.mu.Lock()
		for _, ch := range m.channels {
			ch.close()
		}
		m.mu.Unlock()
	}()
	for {
		c, err := listener.Accept()
		if err != nil {
			return err
		}
		go m.serve(c)
	}
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
