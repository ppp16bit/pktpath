package enrich

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
)

var ErrNoPTR = errors.New("no PTR record")

type ReverseResolver interface {
	Lookup(context.Context, netip.Addr) (string, error)
}

type SystemReverseResolver struct{}

func (SystemReverseResolver) Lookup(ctx context.Context, addr netip.Addr) (string, error) {
	names, err := net.DefaultResolver.LookupAddr(ctx, addr.String())
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) && dnsError.IsNotFound {
			return "", ErrNoPTR
		}
		return "", err
	}
	if len(names) == 0 {
		return "", ErrNoPTR
	}
	return strings.TrimSuffix(names[0], "."), nil
}
