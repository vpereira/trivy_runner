package exec_command

import (
	"testing"
)

func TestNewExecShellCommander(t *testing.T) {
	executor := NewExecShellCommander("echo", "hello")
	execCmd := executor.(*execShellCommand).cmd

	if execCmd.Args[0] != "echo" || len(execCmd.Args) != 2 || execCmd.Args[1] != "hello" {
		t.Errorf("Command was not constructed correctly")
	}
}
