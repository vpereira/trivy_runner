package exec_command

import (
	"os/exec"
)

type IShellCommand interface {
	SetDir(string)
	CombinedOutput() ([]byte, error)
	Wait() error
}

type execShellCommand struct {
	*exec.Cmd
}

func (exc execShellCommand) SetDir(dir string) {
	exc.Dir = dir
}

func (exc execShellCommand) CombinedOutput() ([]byte, error) {
	return exc.Cmd.CombinedOutput()
}

func NewExecShellCommander(name string, arg ...string) IShellCommand {
	execCmd := exec.Command(name, arg...)
	return execShellCommand{Cmd: execCmd}
}
