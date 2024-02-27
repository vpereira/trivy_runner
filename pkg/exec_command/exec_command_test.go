package exec_command

import (
	"testing"
)

func TestNewExecShellCommander(t *testing.T) {
	cmd := NewExecShellCommander("echo", "hello")
	execCmd := cmd.(execShellCommand)

	if execCmd.Args[0] != "echo" || len(execCmd.Args) != 2 || execCmd.Args[1] != "hello" {
		t.Errorf("Command was not constructed correctly")
	}
}

func TestSetDir(t *testing.T) {
	cmd := NewExecShellCommander("pwd")
	execCmd := cmd.(execShellCommand)

	testDir := "/tmp"
	execCmd.SetDir(testDir)

	if execCmd.Dir != testDir {
		t.Errorf("Expected Dir to be %s, got %s", testDir, execCmd.Dir)
	}
}
