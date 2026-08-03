package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kataras/iris/v12"
)

type journalSSEWriter struct {
	value   *journalRequestValue
	context context.Context
	writer  http.ResponseWriter
	flusher http.Flusher
	pending []byte
	failed  error
}

func newJournalSSEWriter(ctx iris.Context, writer http.ResponseWriter) (*journalSSEWriter, http.Flusher) {
	value, ok := ctx.Values().Get(journalRequestValueKey).(*journalRequestValue)
	if !ok || value == nil || value.journal == nil {
		flusher, _ := writer.(http.Flusher)
		return nil, flusher
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		return nil, nil
	}
	wrapped := &journalSSEWriter{
		value:   value,
		context: ctx.Request().Context(),
		writer:  writer,
		flusher: flusher,
	}
	return wrapped, wrapped
}

func (w *journalSSEWriter) Header() http.Header {
	return w.writer.Header()
}

func (w *journalSSEWriter) WriteHeader(statusCode int) {
	w.writer.WriteHeader(statusCode)
}

func (w *journalSSEWriter) Write(payload []byte) (int, error) {
	if w.failed != nil {
		return 0, w.failed
	}
	w.pending = append(w.pending, payload...)
	for {
		separator := bytes.Index(w.pending, []byte("\n\n"))
		if separator < 0 {
			break
		}
		frameEnd := separator + 2
		frame := append([]byte(nil), w.pending[:frameEnd]...)
		w.pending = w.pending[frameEnd:]
		if err := w.forwardFrame(frame); err != nil {
			w.failed = err
			return 0, err
		}
	}
	return len(payload), nil
}

func (w *journalSSEWriter) Flush() {
	if w.failed != nil {
		return
	}
	if len(w.pending) != 0 {
		w.failed = errors.New("incomplete SSE journal frame")
		return
	}
	w.flusher.Flush()
}

func (w *journalSSEWriter) forwardFrame(frame []byte) error {
	body := bytes.TrimSuffix(frame, []byte("\n\n"))
	if !bytes.HasPrefix(body, []byte("data: ")) {
		return errors.New("invalid SSE journal frame")
	}
	payload := bytes.TrimSpace(body[len("data: "):])
	if len(payload) == 0 {
		return errors.New("empty SSE journal payload")
	}
	eventType := "sse.event"
	if bytes.Equal(payload, []byte("[DONE]")) {
		eventType = "stream.done"
	} else {
		var event struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(payload, &event); err == nil && event.Type != "" {
			eventType = event.Type
		}
	}
	return w.value.journal.Forward(w.context, w.value.request, eventType, frame, func(_ context.Context, _ string) error {
		_, err := w.writer.Write(frame)
		if err == nil {
			w.flusher.Flush()
		}
		return err
	})
}
