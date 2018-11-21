package managedwd

import (
	"io/ioutil"
	"os"
)

const (
	defaultWorkdirParent = "/var/tmp"
	defaultWorkdirPrefix = "shstash-"
)

type workdir struct {
	name string
}

func NewWorkdir() (*workdir, error) {
	n, err := ioutil.TempDir(defaultWorkdirParent, defaultWorkdirPrefix)
	return &workdir{name: n}, err
}

func (wd *workdir) Name() string {
	return wd.name
}

func (wd *workdir) Cleanup() error {
	return os.RemoveAll(wd.name)
}
