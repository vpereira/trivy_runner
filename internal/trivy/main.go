package trivy

import "github.com/vpereira/trivy_runner/internal/util"

func GenerateTrivySBOMCmdArgs(resultFileName, target string) []string {
	cmdArgs := []string{"image"}

	// eventually we should support other formats as well
	cmdArgs = append(cmdArgs, "--format", "cyclonedx", "--output", resultFileName, "--input", target)

	return cmdArgs
}

func GenerateTrivyScanCmdArgs(resultFileName, target string) []string {
	cmdArgs := []string{"image"}

	// Check if SLOW_RUN environment variable is set to "1" and add "--slow" parameter
	slowRun := util.GetEnv("SLOW_RUN", "0")
	if slowRun == "1" {
		cmdArgs = append(cmdArgs, "--slow")
	}

	cmdArgs = append(cmdArgs, "--format", "json", "--output", resultFileName, "--input", target)

	return cmdArgs
}
