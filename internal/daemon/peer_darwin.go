package daemon

import (
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func owned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	uid := os.Getuid()
	return ok && uid >= 0 && uint64(stat.Uid) == uint64(uid)
}

func peerAllowed(conn net.Conn) bool {
	uds, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uds.SyscallConn()
	if err != nil {
		return false
	}
	uid := os.Getuid()
	if uid < 0 {
		return false
	}
	expectedUID := uint64(uid)
	allowed := false
	if err = raw.Control(func(fd uintptr) {
		peer, peerErr := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		allowed = peerErr == nil && uint64(peer.Uid) == expectedUID
	}); err != nil {
		return false
	}
	return allowed
}
