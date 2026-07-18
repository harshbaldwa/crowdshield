// Package mock provides an in-memory CrowdSec v1.7.8-shaped LAPI for tests.
// It intentionally does not deduplicate decisions, matching the behavior that
// Crowdshield must handle safely.
package mock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"crowdshield/internal/lapi"
)

type Config struct {
	MachineID       string
	Password        string
	TokenTTL        time.Duration
	Now             func() time.Time
	MaxRequestBytes int64
}

type Server struct {
	server *httptest.Server
	config Config

	mu               sync.Mutex
	tokens           map[string]time.Time
	alerts           map[int64]lapi.Alert
	expiredDecisions map[int64]struct{}
	requests         map[string]int
	requestLog       []string
	nextAlertID      int64
	nextDecisionID   int64
	nextTokenID      int64
	unauthorizedOnce bool
}

type metaItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type event struct {
	Timestamp string     `json:"timestamp"`
	Meta      []metaItem `json:"meta"`
}

type source struct {
	Scope string `json:"scope"`
	Value string `json:"value"`
}

type inboundAlert struct {
	Scenario        string          `json:"scenario"`
	ScenarioHash    string          `json:"scenario_hash"`
	ScenarioVersion string          `json:"scenario_version"`
	Message         string          `json:"message"`
	EventsCount     int             `json:"events_count"`
	StartAt         string          `json:"start_at"`
	StopAt          string          `json:"stop_at"`
	Capacity        int             `json:"capacity"`
	Leakspeed       string          `json:"leakspeed"`
	Simulated       bool            `json:"simulated"`
	Events          []event         `json:"events"`
	Decisions       []lapi.Decision `json:"decisions"`
	Source          source          `json:"source"`
}

func newServer(config Config) *Server {
	if config.MachineID == "" {
		config.MachineID = "crowdshield-test"
	}
	if config.Password == "" {
		config.Password = "mock-password"
	}
	if config.TokenTTL <= 0 {
		config.TokenTTL = time.Hour
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.MaxRequestBytes <= 0 {
		config.MaxRequestBytes = 1 << 20
	}
	return &Server{
		config: config, tokens: make(map[string]time.Time), alerts: make(map[int64]lapi.Alert),
		expiredDecisions: make(map[int64]struct{}), requests: make(map[string]int),
		nextAlertID: 1, nextDecisionID: 1, nextTokenID: 1,
	}
}

// NewHandler returns an in-memory CrowdSec-shaped handler that callers may
// serve on their own bounded listener. It performs no network I/O itself.
func NewHandler(config Config) http.Handler {
	result := newServer(config)
	return http.HandlerFunc(result.serveHTTP)
}

func New(config Config) *Server {
	result := newServer(config)
	result.server = httptest.NewServer(http.HandlerFunc(result.serveHTTP))
	return result
}

func (s *Server) URL() string          { return s.server.URL }
func (s *Server) Close()               { s.server.Close() }
func (s *Server) Client() *http.Client { return s.server.Client() }

func (s *Server) WriteCredentials(directory string) (string, error) {
	path := filepath.Join(directory, "lapi-credentials.yaml")
	body := "url: " + s.URL() + "\nlogin: " + s.config.MachineID + "\npassword: " + s.config.Password + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (s *Server) ForceUnauthorizedOnce() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unauthorizedOnce = true
}

func (s *Server) AddForeignAlert(alert lapi.Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if alert.ID <= 0 {
		alert.ID = s.nextAlertID
	}
	if alert.ID >= s.nextAlertID {
		s.nextAlertID = alert.ID + 1
	}
	for index := range alert.Decisions {
		if alert.Decisions[index].ID <= 0 {
			alert.Decisions[index].ID = s.nextDecisionID
		}
		if alert.Decisions[index].ID >= s.nextDecisionID {
			s.nextDecisionID = alert.Decisions[index].ID + 1
		}
	}
	s.alerts[alert.ID] = alert
}

func (s *Server) Alerts() []lapi.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]lapi.Alert, 0, len(s.alerts))
	for _, alert := range s.alerts {
		clone := alert
		clone.Decisions = append([]lapi.Decision(nil), alert.Decisions...)
		result = append(result, clone)
	}
	return result
}

func (s *Server) WasExpired(decisionID int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.expiredDecisions[decisionID]
	return exists
}

func (s *Server) RequestCount(method, path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[method+" "+path]
}

func (s *Server) RequestLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requestLog...)
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func (s *Server) count(request *http.Request) {
	entry := request.Method + " " + request.URL.Path
	s.requests[entry]++
	s.requestLog = append(s.requestLog, entry)
}

func (s *Server) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count(request)
	if request.URL.Path == "/v1/watchers/login" && request.Method == http.MethodPost {
		s.login(writer, request)
		return
	}
	if !s.authorized(request) {
		writeJSON(writer, http.StatusUnauthorized, map[string]string{"message": "unauthorized"})
		return
	}
	switch {
	case request.URL.Path == "/v1/alerts" && request.Method == http.MethodPost:
		s.createAlerts(writer, request)
	case request.URL.Path == "/v1/alerts" && request.Method == http.MethodGet:
		s.searchAlerts(writer, request)
	case strings.HasPrefix(request.URL.Path, "/v1/alerts/") && request.Method == http.MethodGet:
		s.getAlert(writer, request)
	case strings.HasPrefix(request.URL.Path, "/v1/decisions/") && request.Method == http.MethodDelete:
		s.expireDecision(writer, request)
	default:
		writeJSON(writer, http.StatusNotFound, map[string]string{"message": "not found"})
	}
}

func (s *Server) login(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		MachineID string `json:"machine_id"`
		Password  string `json:"password"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, s.config.MaxRequestBytes))
	if decoder.Decode(&body) != nil || body.MachineID != s.config.MachineID || body.Password != s.config.Password || strings.Count(request.UserAgent(), "/") != 1 {
		writeJSON(writer, http.StatusForbidden, map[string]string{"message": "invalid credentials"})
		return
	}
	token := "mock-token-" + strconv.FormatInt(s.nextTokenID, 10)
	s.nextTokenID++
	expiry := s.config.Now().Add(s.config.TokenTTL).UTC()
	s.tokens[token] = expiry
	writeJSON(writer, http.StatusOK, map[string]any{"code": 200, "expire": expiry.Format(time.RFC3339), "token": token})
}

func (s *Server) authorized(request *http.Request) bool {
	if s.unauthorizedOnce {
		s.unauthorizedOnce = false
		return false
	}
	header := request.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return false
	}
	expiry, exists := s.tokens[strings.TrimPrefix(header, "Bearer ")]
	return exists && expiry.After(s.config.Now())
}

func (s *Server) createAlerts(writer http.ResponseWriter, request *http.Request) {
	var inbound []inboundAlert
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, s.config.MaxRequestBytes))
	if decoder.Decode(&inbound) != nil || len(inbound) != 1 {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"message": "invalid alert batch"})
		return
	}
	item := inbound[0]
	if item.Scenario == "" || item.ScenarioHash == "" || item.ScenarioVersion == "" || item.Message == "" || item.EventsCount != 1 ||
		item.StartAt == "" || item.StopAt == "" || item.Capacity != len(item.Decisions) || item.Leakspeed == "" || len(item.Events) != 1 || item.Source.Scope == "" || item.Source.Value == "" {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"message": "missing required alert fields"})
		return
	}
	alertID := s.nextAlertID
	s.nextAlertID++
	decisions := append([]lapi.Decision(nil), item.Decisions...)
	for index := range decisions {
		decisions[index].ID = s.nextDecisionID
		s.nextDecisionID++
		duration, err := time.ParseDuration(decisions[index].Duration)
		if err != nil || duration <= 0 {
			writeJSON(writer, http.StatusBadRequest, map[string]string{"message": "invalid duration"})
			return
		}
		decisions[index].Until = s.config.Now().Add(duration).UTC().Format(time.RFC3339)
	}
	s.alerts[alertID] = lapi.Alert{
		ID: alertID, MachineID: s.config.MachineID, Scenario: item.Scenario, ScenarioHash: item.ScenarioHash,
		ScenarioVersion: item.ScenarioVersion, Message: item.Message, Decisions: decisions,
	}
	writeJSON(writer, http.StatusCreated, []string{strconv.FormatInt(alertID, 10)})
}

func (s *Server) getAlert(writer http.ResponseWriter, request *http.Request) {
	id, err := strconv.ParseInt(strings.TrimPrefix(request.URL.Path, "/v1/alerts/"), 10, 64)
	alert, exists := s.alerts[id]
	if err != nil || !exists {
		writeJSON(writer, http.StatusNotFound, map[string]string{"message": "not found"})
		return
	}
	writeJSON(writer, http.StatusOK, alert)
}

func (s *Server) searchAlerts(writer http.ResponseWriter, request *http.Request) {
	scenario := request.URL.Query().Get("scenario")
	limit := 100
	if raw := request.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	alerts := make([]lapi.Alert, 0)
	for _, alert := range s.alerts {
		if scenario != "" && alert.Scenario != scenario {
			continue
		}
		alerts = append(alerts, alert)
		if len(alerts) >= limit {
			break
		}
	}
	writeJSON(writer, http.StatusOK, alerts)
}

func (s *Server) expireDecision(writer http.ResponseWriter, request *http.Request) {
	id, err := strconv.ParseInt(strings.TrimPrefix(request.URL.Path, "/v1/decisions/"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(writer, http.StatusNotFound, map[string]string{"message": "not found"})
		return
	}
	for alertID, alert := range s.alerts {
		for index := range alert.Decisions {
			if alert.Decisions[index].ID == id {
				alert.Decisions[index].Until = s.config.Now().UTC().Format(time.RFC3339)
				s.alerts[alertID] = alert
				s.expiredDecisions[id] = struct{}{}
				writeJSON(writer, http.StatusOK, map[string]string{"message": "decision expired"})
				return
			}
		}
	}
	writeJSON(writer, http.StatusNotFound, map[string]string{"message": "not found"})
}
