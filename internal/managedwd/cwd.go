package managedwd

import (
	"io/ioutil"
	"os"
)

const (
	defaultWorkdirRoot   = "/var/tmp"
	defaultWorkdirPrefix = "shstash-"
)

type workdir struct {
	name string
}

func NewWorkdir() (*workdir, error) {
	n, err := ioutil.TempDir(findWorkdirRoot(), defaultWorkdirPrefix)
	return &workdir{name: n}, err
}

func (wd *workdir) Name() string {
	return wd.name
}

func (wd *workdir) Cleanup() error {
	return os.RemoveAll(wd.name)
}

func findWorkdirRoot() string {
	if dir := os.Getenv("SHSTASH_ROOT"); dir != "" {
		return dir
	}
	return defaultWorkdirRoot
}
