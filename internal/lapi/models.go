package lapi

import "time"

type DecisionInput struct {
	Scope string
	Value string
}

type CreateRequest struct {
	FeedName       string
	OperationToken string
	Duration       time.Duration
	Decisions      []DecisionInput
}

type Decision struct {
	ID       int64  `json:"id,omitempty"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Until    string `json:"until,omitempty"`
	Scenario string `json:"scenario"`
}

type Alert struct {
	ID              int64      `json:"id,omitempty"`
	MachineID       string     `json:"machine_id,omitempty"`
	Scenario        string     `json:"scenario"`
	ScenarioHash    string     `json:"scenario_hash"`
	ScenarioVersion string     `json:"scenario_version,omitempty"`
	Message         string     `json:"message,omitempty"`
	Decisions       []Decision `json:"decisions,omitempty"`
}

type wireMetaItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type wireEvent struct {
	Timestamp string         `json:"timestamp"`
	Meta      []wireMetaItem `json:"meta"`
}

type wireSource struct {
	Scope string `json:"scope"`
	Value string `json:"value"`
}

type wireAlert struct {
	Scenario        string         `json:"scenario"`
	ScenarioHash    string         `json:"scenario_hash"`
	ScenarioVersion string         `json:"scenario_version"`
	Message         string         `json:"message"`
	EventsCount     int            `json:"events_count"`
	StartAt         string         `json:"start_at"`
	StopAt          string         `json:"stop_at"`
	Capacity        int            `json:"capacity"`
	Leakspeed       string         `json:"leakspeed"`
	Simulated       bool           `json:"simulated"`
	Events          []wireEvent    `json:"events"`
	Remediation     bool           `json:"remediation"`
	Decisions       []Decision     `json:"decisions"`
	Source          wireSource     `json:"source"`
	Meta            []wireMetaItem `json:"meta"`
	Labels          []string       `json:"labels"`
	Kind            string         `json:"kind"`
}
