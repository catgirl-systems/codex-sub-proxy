package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
)

func main() {
	address := flag.String("listen", "127.0.0.1:0", "listen address")
	flag.Parse()
	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("http://%s\n", listener.Addr().String())
	if err := http.Serve(listener, http.HandlerFunc(responses)); err != nil {
		log.Fatal(err)
	}
}

func responses(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/v1/responses" || request.Method != http.MethodPost {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	_, _ = io.Copy(io.Discard, request.Body)
	_ = request.Body.Close()
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.WriteHeader(http.StatusOK)
	flusher, _ := writer.(http.Flusher)
	_, _ = io.WriteString(writer, "data: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"dry-run-response\",\"object\":\"response\",\"created_at\":1700000000,\"model\":\"gpt-4.1\",\"status\":\"in_progress\"}}\n\n")
	_, _ = io.WriteString(writer, "data: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"delta\":\"dry-run output\"}\n\n")
	_, _ = io.WriteString(writer, "data: {\"type\":\"response.completed\",\"sequence_number\":2,\"response\":{\"id\":\"dry-run-response\",\"object\":\"response\",\"created_at\":1700000000,\"model\":\"gpt-4.1\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":2,\"total_tokens\":3}}}\n\n")
	_, _ = io.WriteString(writer, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}
