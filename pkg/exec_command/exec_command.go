package exec_command

import (
	"os/exec"
)

type IShellCommand interface {
	Output() ([]byte, error)
	NewCommand(string, ...string)
}

type execShellCommand struct {
	cmd *exec.Cmd
}

func (e *execShellCommand) Output() ([]byte, error) {
	return e.cmd.Output()
}

func (e *execShellCommand) NewCommand(name string, arg ...string) {
	e.cmd = exec.Command(name, arg...)
}

func NewExecShellCommander(name string, arg ...string) IShellCommand {
	shellcmd := &execShellCommand{}
	shellcmd.NewCommand(name, arg...)
	return shellcmd
}
