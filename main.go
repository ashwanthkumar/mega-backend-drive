package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// Job is the input job specification
type Job struct {
	ID       string `json:"id"`
	User     string `json:"user"`
	AlgAsStr string `json:"alg"`
	Payload  string `json:"payload"`
}

// IsValid checks if the parsed Job is valid or not
func (j *Job) IsValid() bool {
	if "" == j.ID || "" == j.User || "" == j.AlgAsStr || "" == j.Payload {
		return false
	}
	// check if the input algo is valid
	if "" == HashValue("", j.AlgAsStr) {
		return false
	}

	return true
}

// Reply is the output job specification
type Reply struct {
	ID      string `json:"id"`
	Output  string `json:"output"`
	Success bool   `json:"success"`
	User    string `json:"user"`
}

// HashingService is a one-way hashing service over a chat like interface
type HashingService struct {
	Input  *os.File
	Output *os.File

	inputChannel  chan *Job
	outputChannel chan *Reply

	inFlight sync.WaitGroup
	blocking sync.WaitGroup
}

// BlockingStart starts the hashing service and waits until it's stopped
func (h *HashingService) BlockingStart() {
	h.inputChannel = make(chan *Job, 512) // processing is slow, so we need a larger bufer here
	h.outputChannel = make(chan *Reply, 128)

	h.blocking.Add(1)
	go h.readInput()
	go h.processJobs()
	go h.printOutput()
	h.blocking.Wait()
}

// readInput reads from Input, parse the JSON and queues it for processing
func (h *HashingService) readInput() {
	reader := bufio.NewReader(h.Input)
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			break
		}
		var job Job
		jsonErr := json.Unmarshal([]byte(line), &job)
		if jsonErr == nil && job.IsValid() {
			h.inFlight.Add(1)
			h.inputChannel <- &job
		}

		if err == io.EOF {
			break
		}
	}
	close(h.inputChannel)
	h.Stop()
}

// Unfornately we can't process multiple inputs in parallel,
// because the checker is a little dumb and expects the outputs
// in the same order as the input
func (h *HashingService) processJobs() {
	for job := range h.inputChannel {
		h.inFlight.Add(1)
		h.inFlight.Done()
		reply := jobToReply(job)
		h.outputChannel <- reply
	}
	close(h.outputChannel)
}

// printOutput makes sure we write only 1 record in each line
// even while processing multiple jobs concurrently
func (h *HashingService) printOutput() {
	for reply := range h.outputChannel {
		jsonAsBytes, err := json.Marshal(reply)
		if err == nil {
			fmt.Fprintf(h.Output, "%s\n", jsonAsBytes)
		}
		h.inFlight.Done()
	}
}

// Stop the hashing service
func (h *HashingService) Stop() {
	h.inFlight.Wait()
	h.blocking.Done()
}

// Convert the input Job To Reply that needs to be sent out
func jobToReply(job *Job) *Reply {
	reply := &Reply{
		ID:      job.ID,
		User:    job.User,
		Success: true,
	}
	hashedValue := HashValue(job.Payload, job.AlgAsStr)
	if "" == hashedValue {
		reply.Success = false
	} else {
		reply.Output = hashedValue
	}
	return reply
}

// HashValue tries to hash the input string using the algorithm
func HashValue(input string, algorithm string) string {
	switch algorithm {
	case "SHA1":
		return fmt.Sprintf("%x", sha1.Sum([]byte(input)))
	case "SHA256":
		return fmt.Sprintf("%x", sha256.Sum256([]byte(input)))
	case "SHA512":
		return fmt.Sprintf("%x", sha512.Sum512([]byte(input)))
	case "MD5":
		return fmt.Sprintf("%x", md5.Sum([]byte(input)))
	default:
		return ""
	}
}

func main() {
	service := HashingService{
		Input:  os.Stdin,
		Output: os.Stdout,
	}
	service.BlockingStart()
}
