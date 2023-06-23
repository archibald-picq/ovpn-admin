package shell

import (
	"net"
	"sort"
	"strings"
)

// Get preferred outbound ip of this machine

type rankedIp struct {
	rank int
	ip   net.IP
}

func GetOutboundIP() net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var rankedIps = make([]rankedIp, 0)
	// handle err
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		// handle err
		for _, addr := range addrs {

			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				//log.Printf("Found ip %s", ip)
			case *net.IPAddr:
				ip = v.IP
				//log.Printf("Found ip %s", ip)
			}
			if strings.HasPrefix(ip.String(), "127.0.0.") {
				// dont connect to loopback
				rankedIps = append(rankedIps, rankedIp{ip: ip, rank: 1})
			} else if strings.HasPrefix(ip.String(), "172.") {
				// dont connect to docker
				rankedIps = append(rankedIps, rankedIp{ip: ip, rank: 2})
			} else if strings.HasPrefix(ip.String(), "169.254.") {
				// dont connect to default assigned address
				rankedIps = append(rankedIps, rankedIp{ip: ip, rank: 2})
			} else if strings.HasPrefix(ip.String(), "10.") {
				// dont connect to internal network
				rankedIps = append(rankedIps, rankedIp{ip: ip, rank: 3})
			} else if !ip.IsPrivate() && ip.To4() != nil {
				// prefer ipv4 public address
				rankedIps = append(rankedIps, rankedIp{ip: ip, rank: 5})
			} else if !ip.IsPrivate() && ip.To4() == nil {
				// then prefer ipv6 public address
				rankedIps = append(rankedIps, rankedIp{ip: ip, rank: 3})
			} else if ip.IsPrivate() && ip.To4() != nil {
				// but still if there is private ipv4, it's better
				rankedIps = append(rankedIps, rankedIp{ip: ip, rank: 4})
			} else if strings.HasPrefix(ip.String(), ":") {
				rankedIps = append(rankedIps, rankedIp{ip: ip, rank: 1})
			} else {
				rankedIps = append(rankedIps, rankedIp{ip: ip, rank: 1})
			}
			// process IP address
		}
	}
	sort.Slice(rankedIps, func(i, j int) bool {
		return rankedIps[i].rank > rankedIps[j].rank
	})
	//for _, ranked := range rankedIps {
	//	log.Printf("ranked: %d => %s", ranked.rank, ranked.ip)
	//}
	return rankedIps[0].ip
}
