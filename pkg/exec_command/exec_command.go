package exec_command

import (
	"os/exec"
)

type IShellCommand interface {
	SetDir(string)
	Output() ([]byte, error)
	Wait() error
}

type execShellCommand struct {
	*exec.Cmd
}

func (exc execShellCommand) SetDir(dir string) {
	exc.Dir = dir
}

func NewExecShellCommander(name string, arg ...string) IShellCommand {
	execCmd := exec.Command(name, arg...)
	return execShellCommand{Cmd: execCmd}
}
