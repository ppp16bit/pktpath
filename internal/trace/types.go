package trace

import (
	"net/netip"
	"time"
)

type Hop struct {
	Number      int
	IP          netip.Addr
	RTT         time.Duration
	ReceivedAt  time.Time
	Timeout     bool
	Reached     bool
	Unreachable bool
}

type Result struct {
	Destination string
	Target      netip.Addr
	Probe       string
	PacketSize  int
	StartedAt   time.Time
	Hops        []Hop
	Reached     bool
}

type Config struct {
	MaxHops    int
	Timeout    time.Duration
	PacketSize int
}

const (
	MinIPv4ICMPPacketSize = 28
	MaxIPv4PacketSize     = 65535
)

func DefaultConfig() Config {
	return Config{MaxHops: 30, Timeout: 2 * time.Second, PacketSize: 64}
}

func (c Config) Validate() error {
	if c.MaxHops < 1 || c.MaxHops > 255 {
		return newConfigError("max hops must be between 1 and 255")
	}
	if c.Timeout <= 0 {
		return newConfigError("timeout must be greater than zero")
	}
	if c.PacketSize < MinIPv4ICMPPacketSize || c.PacketSize > MaxIPv4PacketSize {
		return newConfigError("packet size must be between 28 and 65535 bytes")
	}
	return nil
}

type configError string

func newConfigError(message string) error { return configError(message) }
func (e configError) Error() string       { return string(e) }
