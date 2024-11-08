package main

import (
	"fmt"
	"log"
	"time"

	. "github.com/compliance-framework/assessment-runtime/provider"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

// SSHCommandProvider is ...
type SSHCommandProvider struct {
	message    string
	RunCommand func(SSHConfig) (string, int, error)
}

// SSHConfig contains the SSH connection configuration
type SSHConfig struct {
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
	Host     string `json:"host" yaml:"host"`
	Command  string `json:"command" yaml:"command"`
	Pem      string `json:"pem" yaml:"pem"`
	Port     string `json:"port,omitempty" yaml:"port,omitempty"`
}

func (p *SSHCommandProvider) Evaluate(input *EvaluateInput) (*EvaluateResult, error) {
	var sshConfig SSHConfig

	yamlString, ok := input.Configuration["yaml"]
	log.Printf("yamlString: %s", yamlString)

	err := yaml.Unmarshal([]byte(yamlString), &sshConfig)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling YAML: %v", err)
	}
	if !ok {
		return nil, fmt.Errorf("yaml parameter is missing")
	}

	username := sshConfig.Username
	host := sshConfig.Host
	command := sshConfig.Command
	port := sshConfig.Port
	if port == "" {
		port = "22" // default to 22 if no port supplied``
	}

	// There is only one subject, so create one
	subjects := make([]*Subject, 0)
	sshTargetId := fmt.Sprintf("%s@%s:%s %s", username, host, port, command)
	subjects = append(subjects, &Subject{
		Id:    sshTargetId,
		Type:  SubjectType_INVENTORY_ITEM,
		Title: fmt.Sprintf("SSH target ssh %s", sshTargetId),
		Props: map[string]string{
			"id": sshTargetId,
		},
	})

	// Return the result with subjects and additional props if necessary
	return &EvaluateResult{
		Subjects: subjects,
	}, nil
}

func (p *SSHCommandProvider) Execute(input *ExecuteInput) (*ExecuteResult, error) {
	if p.RunCommand == nil {
		return nil, fmt.Errorf("RunCommand function is not set")
	}

	startTime := time.Now().Format(time.RFC3339)

	var sshConfig SSHConfig

	yamlString, ok := input.Configuration["yaml"]
	if !ok {
		return nil, fmt.Errorf("yaml parameter is missing")
	}

	err := yaml.Unmarshal([]byte(yamlString), &sshConfig)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling YAML: %v", err)
	}

	output, exitCode, err := p.RunCommand(sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to run command: %v", err)
	}

	observations := []*Observation{}
	findings := []*Finding{}
	obsId := uuid.New().String()
	sshTargetCommand := fmt.Sprintf("ssh -p %s %s@%s %s", sshConfig.Port, sshConfig.Username, sshConfig.Host, sshConfig.Command)

	if exitCode != 0 {
		observations = append(observations, &Observation{
			Id:          obsId,
			Title:       "SSH Command Did Not Succeed",
			Description: fmt.Sprintf("The command: %s did not succeed.", sshTargetCommand),
			Collected:   time.Now().Format(time.RFC3339),
			Expires:     time.Now().AddDate(0, 1, 0).Format(time.RFC3339),
			Links:       []*Link{},
			Props: []*Property{
				{
					Name:  "Command",
					Value: sshTargetCommand,
				},
			},
			RelevantEvidence: []*Evidence{
				{
					Description: fmt.Sprintf("The command returned an exit code of %d for the command: %s", exitCode, sshTargetCommand),
				},
			},
			Remarks: fmt.Sprintf("The command: '%s' should return a zero exit code.", sshTargetCommand),
		})
		findings = append(findings, &Finding{
			Id:                  uuid.New().String(),
			Title:               "SSH Command Failure",
			Description:         fmt.Sprintf("The command %s did not succeed, and produced output: %s.", sshTargetCommand, output),
			Remarks:             fmt.Sprintf("Correct the command %s.", sshTargetCommand),
			RelatedObservations: []string{obsId},
		})
	} else {
		observations = append(observations, &Observation{
			Id:          obsId,
			Title:       "SSH Command Succeeded",
			Description: fmt.Sprintf("The command: %s succeeded.", sshTargetCommand),
			Collected:   time.Now().Format(time.RFC3339),
			Expires:     time.Now().AddDate(0, 1, 0).Format(time.RFC3339), // Add one month for the expiration
			Links:       []*Link{},
			Props: []*Property{
				{
					Name:  "Command",
					Value: sshTargetCommand,
				},
			},
			RelevantEvidence: []*Evidence{
				{
					Description: fmt.Sprintf("The command returned an exit code of %d for the command: %s", exitCode, sshTargetCommand),
				},
			},
			Remarks: "All OK.",
		})
	}

	// Log that the check has successfully run
	logEntry := &LogEntry{
		Title:       "SSH Command Check",
		Description: "SSH command check has run successfully",
		Start:       startTime,
		End:         time.Now().Format(time.RFC3339),
	}

	return &ExecuteResult{
		Status:       ExecutionStatus_SUCCESS,
		Observations: observations,
		Findings:     findings,
		Logs:         []*LogEntry{logEntry},
	}, nil
}

// LoadPrivateKeyFromConfig : Converts the PEM string into bytes and parse it
func LoadPrivateKeyFromConfig(config SSHConfig) (ssh.Signer, error) {
	key := []byte(config.Pem)

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %v", err)
	}

	return signer, nil
}

// RunCommand executes a command on the remote server over SSH and returns the output
func RunCommand(config SSHConfig) (string, int, error) {

	// Load the private key from the config
	signer, err := LoadPrivateKeyFromConfig(config)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	sshConfig := &ssh.ClientConfig{
		User: config.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Insecure: For testing only, consider verifying host key
	}

	// Establish the SSH connection
	address := fmt.Sprintf("%s:%s", config.Host, config.Port)
	client, err := ssh.Dial("tcp", address, sshConfig)
	if err != nil {
		return "", -1, fmt.Errorf("failed to dial: %v", err)
	}
	defer client.Close()

	// Create a session for the command execution
	session, err := client.NewSession()
	if err != nil {
		return "", -1, fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// Execute the command and capture the output
	output, err := session.CombinedOutput(config.Command)
	exitCode := -1
	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			exitCode = exitErr.ExitStatus()
		} else {
			return "", -1, fmt.Errorf("failed to execute command: %v", err)
		}
	} else {
		exitCode = 0
	}

	return string(output), exitCode, nil
}

func main() {
	provider := &SSHCommandProvider{
		message:    "Azure CLI provider completed",
		RunCommand: RunCommand,
	}
	Register(provider)
}
