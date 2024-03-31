package openvpn

import (
	"fmt"
	"github.com/seancfoley/ipaddress-go/ipaddr"
	"strings"
)

func ConvertNetworkMaskCidr(addrMask string) string {
	parts := strings.Fields(addrMask)
	if len(parts) <= 1 {
		return ""
	}
	pref := ipaddr.NewIPAddressString(parts[1]).GetAddress().GetBlockMaskPrefixLen(true)
	return fmt.Sprintf("%s/%d", parts[0], pref.Len())
}
