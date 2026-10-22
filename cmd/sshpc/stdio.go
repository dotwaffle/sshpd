package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// pollableFile gives inherited pipes and sockets cancellable Go I/O.
// os.Stdin and os.Stdout can wrap blocking descriptors without a runtime poller.
func pollableFile(file *os.File) (*os.File, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Mode().IsRegular() {
		return file, nil
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var duplicateErr error
	if err := raw.Control(func(original uintptr) {
		fd, duplicateErr = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 0)
	}); err != nil {
		return nil, err
	}
	if duplicateErr != nil {
		return nil, fmt.Errorf("duplicate proxy descriptor: %w", duplicateErr)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("make proxy descriptor nonblocking: %w", err)
	}
	return os.NewFile(uintptr(fd), file.Name()), nil
}
