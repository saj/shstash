package managedwd

type Cmd interface {
	Run() error
	Start() error
	Wait() error
	Terminate() error
	Kill() error
}
