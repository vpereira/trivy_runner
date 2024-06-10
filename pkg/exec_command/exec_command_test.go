package exec_command

import (
	"testing"

	"github.com/vpereira/trivy_runner/pkg/exec_command/mocks"
	"go.uber.org/mock/gomock"
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

// Test our MockIShellCommand
func TestExecCommandWithMock(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockShellCommand := mocks.NewMockIShellCommand(ctrl)

	mockShellCommand.EXPECT().CombinedOutput().Return([]byte("output"), nil)

	// Using the mock
	output, err := mockShellCommand.CombinedOutput()

	// Assertions
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}
	if string(output) != "output" {
		t.Errorf("Expected output to be 'output', but got %s", string(output))
	}
}
