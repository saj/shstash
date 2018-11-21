package managedwd

import (
	"os"
	"os/exec"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func NewShell() Cmd {
	c := exec.Command(findShell())
	setExecCmdFds(c)
	return &shell{cmd: c}
}

func NewShellWithArgs(arg ...string) Cmd {
	c := exec.Command(findShell(), arg...)
	setExecCmdFds(c)
	return &shell{cmd: c}
}

func setExecCmdFds(c *exec.Cmd) {
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
}

type shell struct {
	cmd *exec.Cmd

	mu sync.Mutex
	wd *workdir
}

func (s *shell) Run() error {
	if err := s.Start(); err != nil {
		return err
	}
	return s.Wait()
}

func (s *shell) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wd != nil {
		return errors.Wrap(errors.New("cmd already started"), "managedwd")
	}
	wd, err := NewWorkdir()
	if err != nil {
		return errors.Wrap(err, "managedwd")
	}
	s.wd = wd
	s.cmd.Dir = wd.Name()
	return s.cmd.Start()
}

func (s *shell) Wait() (err error) {
	s.mu.Lock()
	if s.wd == nil {
		s.mu.Unlock()
		return errors.Wrap(errors.New("cmd not started"), "managedwd")
	}
	s.mu.Unlock()

	defer func() {
		cleanupError := s.wd.Cleanup()
		if err == nil {
			err = errors.Wrap(cleanupError, "managedwd")
		}
	}()
	err = s.cmd.Wait()
	return
}

func (s *shell) Terminate() error {
	p := s.cmd.Process
	if p == nil {
		return errors.Wrap(errors.New("cmd not started"), "managedwd")
	}
	return p.Signal(unix.SIGTERM)
}

func (s *shell) Kill() error {
	p := s.cmd.Process
	if p == nil {
		return errors.Wrap(errors.New("cmd not started"), "managedwd")
	}
	return p.Kill()
}

func findShell() string {
	envs := []string{"SHSTASH_SHELL", "SHELL"}
	if s, ok := findShellByEnv(envs); ok {
		return s
	}
	return "sh"
}

func findShellByEnv(keys []string) (string, bool) {
	for _, k := range keys {
		s, ok := os.LookupEnv(k)
		if ok && len(s) > 0 {
			return s, true
		}
	}
	return "", false
}
