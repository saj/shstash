package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/saj/shstash/internal/managedwd"
	"golang.org/x/sys/unix"
)

func main() {
	sh := managedwd.NewShellWithArgs(os.Args[1:]...)

	go handleSignals(sh)

	if err := sh.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if unixError, ok := exitError.Sys().(syscall.WaitStatus); ok {
				os.Exit(unixError.ExitStatus())
			}
			fmt.Fprintf(os.Stderr, "pid %d: %v\n", exitError.Pid(), exitError)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func handleSignals(cmd managedwd.Cmd) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, unix.SIGINT, unix.SIGQUIT, unix.SIGTERM)
	for {
		select {
		case s := <-sigs:
			var err error
			switch s {
			case unix.SIGQUIT:
				err = cmd.Kill()
			default:
				err = cmd.Terminate()
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}
	}
}
