package pull_worker

import (
	"errors"
	"reflect"
	"testing"
)

type fakeExecutor struct {
	Command      []string
	MockedStdout []byte
	MockedError  error
}

func (f *fakeExecutor) Output() ([]byte, error) {
	return f.MockedStdout, f.MockedError
}

func (f *fakeExecutor) NewCommand(name string, arg ...string) {
	f.Command = append([]string{name}, arg...)
}

func TestPullWorkerHappyPath(t *testing.T) {
	imageName := "registry.example.com/myimage:latest"
	targetDir := "/tmp/targetdir"
	expectedResult := []string{
		"skopeo",
		"copy", "--remove-signatures",
		"docker://registry.example.com/myimage:latest",
		"oci:///tmp/targetdir",
	}

	executor := &fakeExecutor{}
	puller := NewPuller(executor)
	puller.Pull(imageName, targetDir)

	if !reflect.DeepEqual(executor.Command, expectedResult) {
		t.Errorf("Puller(%s, %s) executed %v, want %v", imageName, targetDir, executor.Command, expectedResult)
	}
}

func TestRaiseError(t *testing.T) {
	executor := &fakeExecutor{}
	executor.MockedError = errors.New("signal: killed")

	puller := NewPuller(executor)
	res := puller.Pull("", "abc")

	if res == nil {
		t.Fatal("Expected error, got nil")
	}

	if res != NoImageGiven {
		t.Fatalf("Expected %v, got %v", NoImageGiven, res)
	}
}

func TestNoImage(t *testing.T) {
	imageName := "registry.example.com/myimage:latest"
	targetDir := "/tmp/targetdir"

	executor := &fakeExecutor{}
	executor.MockedError = errors.New("signal: killed")

	puller := NewPuller(executor)
	res := puller.Pull(imageName, targetDir)

	if res == nil {
		t.Fatal("Expected error, got nil")
	}

	if res != executor.MockedError {
		t.Fatal("Executor failed for the wrong reasons")
	}
}
