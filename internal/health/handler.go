package health

import (
	"encoding/json"
	"net/http"
)

type healthResponse struct {
	Status string `json:"status"`
}

func setJSONHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
}

func methodAllowed(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method == http.MethodGet || request.Method == http.MethodHead {
		return true
	}
	writer.Header().Set("Allow", "GET, HEAD")
	http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func writeJSON(writer http.ResponseWriter, request *http.Request, status int, value any) {
	setJSONHeaders(writer)
	writer.WriteHeader(status)
	if request.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(writer).Encode(value)
}

// NewHandler returns an exact-path observability router for liveness,
// readiness, and Prometheus metrics.
func NewHandler(tracker *Tracker, metricHandler http.Handler) (http.Handler, error) {
	if tracker == nil || metricHandler == nil {
		return nil, ErrInvalidOptions
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if !methodAllowed(writer, request) {
			return
		}
		writeJSON(writer, request, http.StatusOK, healthResponse{Status: "alive"})
	})
	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, request *http.Request) {
		if !methodAllowed(writer, request) {
			return
		}
		state := tracker.Snapshot()
		status := http.StatusServiceUnavailable
		if state.Status == StatusReady {
			status = http.StatusOK
		}
		writeJSON(writer, request, status, state)
	})
	mux.Handle("/metrics", metricHandler)
	return mux, nil
}
