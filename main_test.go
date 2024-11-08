package main

import (
	"testing"

	. "github.com/compliance-framework/assessment-runtime/provider"
	"github.com/stretchr/testify/assert"
)

func mockRunCommandSuccess(config SSHConfig) (string, int, error) {
	return "Success output", 0, nil
}

func mockRunCommandFailure(config SSHConfig) (string, int, error) {
	// Simulate a command failure with a non-zero exit code but no error
	return "Simulated failure output", 1, nil
}

func TestExecute_Success(t *testing.T) {
	provider := &SSHCommandProvider{
		RunCommand: mockRunCommandSuccess,
	}

	input := &ExecuteInput{
		Configuration: map[string]string{
			"yaml": `
username: testuser
host: example.com
command: uptime
port: "22"
pem: "mockpemkey"
`,
		},
	}

	result, err := provider.Execute(input)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, ExecutionStatus_SUCCESS, result.Status)
	assert.Len(t, result.Observations, 1)
	assert.Empty(t, result.Findings)
	assert.Equal(t, "SSH Command Succeeded", result.Observations[0].Title)
}

func TestExecute_Failure(t *testing.T) {
	provider := &SSHCommandProvider{
		RunCommand: mockRunCommandFailure,
	}

	input := &ExecuteInput{
		Configuration: map[string]string{
			"yaml": `
username: testuser
host: example.com
command: uptime
port: "22"
pem: "mockpemkey"
`,
		},
	}

	// Call the Execute function
	result, err := provider.Execute(input)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}

	if result == nil {
		t.Fatal("expected a result, but got nil")
	}

	// Validate observations and findings
	if len(result.Observations) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(result.Observations))
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	assert.Equal(t, "SSH Command Did Not Succeed", result.Observations[0].Title)
	assert.Equal(t, "SSH Command Failure", result.Findings[0].Title)
}
