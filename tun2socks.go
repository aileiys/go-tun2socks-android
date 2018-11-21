package tun2socks

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	vcore "v2ray.com/core"
	vproxyman "v2ray.com/core/app/proxyman"
	vbytespool "v2ray.com/core/common/bytespool"
	vnet "v2ray.com/core/common/net"
	vinternet "v2ray.com/core/transport/internet"

	"github.com/eycorsican/go-tun2socks/core"
	"github.com/eycorsican/go-tun2socks/proxy/v2ray"
)

var err error
var lwipStack core.LWIPStack
var v *vcore.Instance
var isStopped = false

type VpnService interface {
	Protect(fd int)
}

type PacketFlow interface {
	WritePacket(packet []byte)
}

func InputPacket(data []byte) {
	lwipStack.Write(data)
}

func StartV2Ray(packetFlow PacketFlow, vpnService VpnService, configBytes []byte, assetPath, exceptionDomains, exceptionIPs string) {
	if packetFlow != nil {
		if lwipStack == nil {
			lwipStack = core.NewLWIPStack()
		}

		os.Setenv("v2ray.location.asset", assetPath)

		domains := strings.Split(exceptionDomains, ",")
		ips := strings.Split(exceptionIPs, ",")
		var domainIPMap = make(map[string]string, len(domains))
		for idx, _ := range domains {
			domainIPMap[domains[idx]] = ips[idx]
		}
		vinternet.UseAlternativeSystemDialer(&protectedDialer{
			vpnService:       vpnService,
			proxyDomainIPMap: domainIPMap,
		})

		core.SetBufferPool(vbytespool.GetPool(core.BufSize))

		v, err = vcore.StartInstance("json", configBytes)
		if err != nil {
			log.Fatal("start V instance failed: %v", err)
		}

		sniffingConfig := &vproxyman.SniffingConfig{
			Enabled:             true,
			DestinationOverride: strings.Split("tls,http", ","),
		}
		ctx := vproxyman.ContextWithSniffingConfig(context.Background(), sniffingConfig)

		vhandler := v2ray.NewHandler(ctx, v)
		core.RegisterTCPConnectionHandler(vhandler)
		core.RegisterUDPConnectionHandler(vhandler)

		core.RegisterOutputFn(func(data []byte) (int, error) {
			if !isStopped {
				packetFlow.WritePacket(data)
			}
			return len(data), nil
		})

		isStopped = false
	}
}

func StopV2Ray() {
	isStopped = true
	lwipStack.Close()
	v.Close()
}

type protectedDialer struct {
	vpnService       VpnService
	proxyDomainIPMap map[string]string
}

func (d protectedDialer) Dial(ctx context.Context, src vnet.Address, dest vnet.Destination) (net.Conn, error) {
	if dest.Address.Family().IsDomain() {
		if ip, found := d.proxyDomainIPMap[dest.Address.String()]; found {
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				panic("impossible nil IP")
			}
			dest.Address = vnet.IPAddress(parsedIP)
		} else {
			addr, err := net.ResolveTCPAddr("tcp", dest.NetAddr())
			if err != nil {
				return nil, errors.New(fmt.Sprintf("failed to resolve address %v: %v", dest.NetAddr(), err))
			}
			dest.Address = vnet.IPAddress(addr.IP)
		}
	}

	sa := &unix.SockaddrInet6{Port: int(dest.Port.Value())}
	copy(sa.Addr[:], dest.Address.IP().To16())

	if dest.Network == vnet.Network_TCP {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to create unix socket: %v", err))
		}

		// protect fd from VPN service
		d.vpnService.Protect(fd)

		err = unix.Connect(fd, sa)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to connect: %v", err))
		}

		file := os.NewFile(uintptr(fd), "Socket")
		conn, err := net.FileConn(file)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to create FileConn from fd: %v", err))
		}

		return conn, nil
	} else if dest.Network == vnet.Network_UDP {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to create unix socket: %v", err))
		}

		// protect fd from VPN service
		d.vpnService.Protect(fd)

		err = unix.Connect(fd, sa)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to connect: %v", err))
		}

		file := os.NewFile(uintptr(fd), "Socket")
		conn, err := net.FileConn(file)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to create FileConn from fd: %v", err))
		}

		return conn, nil

	} else {
		return nil, errors.New("unsupported network protocol")
	}
}
