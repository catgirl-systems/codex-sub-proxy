package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type responseEnvelope struct {
	ID     string          `json:"id"`
	Object string          `json:"object"`
	Status string          `json:"status"`
	Output json.RawMessage `json:"output"`
}

func main() {
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 16<<20))
	var response responseEnvelope
	if err := decoder.Decode(&response); err != nil {
		fail(fmt.Sprintf("decode Responses response: %v", err))
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		fail("Responses response contains trailing data")
	}
	if strings.TrimSpace(response.ID) == "" || response.Object != "response" || strings.TrimSpace(response.Status) == "" || len(response.Output) == 0 || bytes.Equal(bytes.TrimSpace(response.Output), []byte("null")) {
		fail("Responses response fields are invalid")
	}
	var output []json.RawMessage
	if err := json.Unmarshal(response.Output, &output); err != nil {
		fail(fmt.Sprintf("Responses output is invalid: %v", err))
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
