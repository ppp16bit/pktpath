package network

import "net/netip"

type Class string

const (
	ClassInvalid   Class = "invalid"
	ClassPrivate   Class = "private"
	ClassLoopback  Class = "loopback"
	ClassLinkLocal Class = "link-local"
	ClassMulticast Class = "multicast"
	ClassShared    Class = "shared" // RFC 6598 shared address space (possible CGNAT)
	ClassPublic    Class = "public"
)

var sharedIPv4 = netip.MustParsePrefix("100.64.0.0/10")

func Classify(addr netip.Addr) Class {
	if !addr.IsValid() {
		return ClassInvalid
	}
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return ClassLoopback
	}
	if addr.IsLinkLocalUnicast() {
		return ClassLinkLocal
	}
	if addr.IsMulticast() {
		return ClassMulticast
	}
	if addr.Is4() && sharedIPv4.Contains(addr) {
		return ClassShared
	}
	if addr.IsPrivate() {
		return ClassPrivate
	}
	return ClassPublic
}

func CanGeolocate(addr netip.Addr) bool {
	return Classify(addr) == ClassPublic
}
