package trace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func probe(ctx context.Context, conn *icmp.PacketConn, target netip.Addr, id, sequence int, cfg Config) (Hop, error) {
	hop := Hop{Number: sequence, Timeout: true}
	payload := make([]byte, cfg.PacketSize-MinIPv4ICMPPacketSize)
	message := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: sequence, Data: payload},
	}
	packet, err := message.Marshal(nil)
	if err != nil {
		return hop, fmt.Errorf("marshal probe %d: %w", sequence, err)
	}

	sentAt := time.Now()
	if _, err := conn.WriteTo(packet, &net.IPAddr{IP: net.IP(target.AsSlice())}); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return hop, ctxErr
		}
		return hop, fmt.Errorf("send probe %d: %w", sequence, err)
	}
	deadline := sentAt.Add(cfg.Timeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return hop, fmt.Errorf("set probe %d deadline: %w", sequence, err)
	}

	buffer := make([]byte, 1500)
	for {
		if err := ctx.Err(); err != nil {
			return hop, err
		}
		n, peer, err := conn.ReadFrom(buffer)
		receivedAt := time.Now()
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return hop, ctxErr
			}
			if isTimeout(err) {
				return hop, nil
			}
			return hop, fmt.Errorf("receive response for probe %d: %w", sequence, err)
		}

		matched, reached, unreachable := matchResponse(buffer[:n], id, sequence)
		if !matched {
			continue
		}
		peerIP, ok := peerAddr(peer)
		if !ok {
			continue
		}
		if reached && peerIP != target {
			continue
		}
		hop.IP = peerIP
		hop.RTT = receivedAt.Sub(sentAt)
		hop.ReceivedAt = receivedAt
		hop.Timeout = false
		hop.Reached = reached && peerIP == target
		hop.Unreachable = unreachable
		return hop, nil
	}
}

func matchResponse(packet []byte, id, sequence int) (matched, reached, unreachable bool) {
	message, err := icmp.ParseMessage(1, packet)
	if err != nil {
		return false, false, false
	}
	switch message.Type {
	case ipv4.ICMPTypeEchoReply:
		echo, ok := message.Body.(*icmp.Echo)
		return ok && echo.ID == id && echo.Seq == sequence, true, false
	case ipv4.ICMPTypeTimeExceeded:
		body, ok := message.Body.(*icmp.TimeExceeded)
		return ok && matchesQuotedEcho(body.Data, id, sequence), false, false
	case ipv4.ICMPTypeDestinationUnreachable:
		body, ok := message.Body.(*icmp.DstUnreach)
		return ok && matchesQuotedEcho(body.Data, id, sequence), false, true
	default:
		return false, false, false
	}
}

func matchesQuotedEcho(data []byte, id, sequence int) bool {
	header, err := ipv4.ParseHeader(data)
	if err != nil || header.Protocol != 1 || header.Len > len(data) {
		return false
	}
	message, err := icmp.ParseMessage(1, data[header.Len:])
	if err != nil || message.Type != ipv4.ICMPTypeEcho {
		return false
	}
	echo, ok := message.Body.(*icmp.Echo)
	return ok && echo.ID == id && echo.Seq == sequence
}

func peerAddr(addr net.Addr) (netip.Addr, bool) {
	if addr == nil {
		return netip.Addr{}, false
	}
	var ip net.IP
	switch value := addr.(type) {
	case *net.IPAddr:
		ip = value.IP
	default:
		parsed := net.ParseIP(addr.String())
		if parsed == nil {
			return netip.Addr{}, false
		}
		ip = parsed
	}
	result, ok := netip.AddrFromSlice(ip)
	return result.Unmap(), ok
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
