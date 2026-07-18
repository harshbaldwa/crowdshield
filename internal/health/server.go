package health

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"crowdshield/internal/ops"
)

var (
	ErrAlreadyServing  = errors.New("HTTP server already serving")
	ErrServe           = errors.New("HTTP server failure")
	ErrShutdown        = errors.New("HTTP shutdown failure")
	ErrShutdownTimeout = errors.New("HTTP shutdown timeout")
)

type Observer interface {
	Observe(context.Context, ops.Event)
}

type noopObserver struct{}

func (noopObserver) Observe(context.Context, ops.Event) {}

type ServerOptions struct {
	Handler  http.Handler
	Clock    Clock
	Observer Observer
	ErrorLog *log.Logger

	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
}

type Server struct {
	httpServer      *http.Server
	clock           Clock
	observer        Observer
	shutdownTimeout time.Duration

	serving      atomic.Bool
	shutdownOnce sync.Once
	shutdownDone chan struct{}
	shutdownMu   sync.Mutex
	shutdownErr  error
}

func validServerTimeout(value time.Duration) bool {
	return value > 0 && value <= 10*time.Minute
}

func NewServer(options ServerOptions) (*Server, error) {
	if options.Handler == nil || !validServerTimeout(options.ReadHeaderTimeout) ||
		!validServerTimeout(options.ReadTimeout) || !validServerTimeout(options.WriteTimeout) ||
		!validServerTimeout(options.IdleTimeout) || !validServerTimeout(options.ShutdownTimeout) {
		return nil, ErrInvalidOptions
	}
	if options.Clock == nil {
		options.Clock = systemClock{}
	}
	if options.Observer == nil {
		options.Observer = noopObserver{}
	}
	if options.ErrorLog == nil {
		options.ErrorLog = log.New(io.Discard, "", 0)
	}
	return &Server{
		httpServer: &http.Server{
			Handler:           options.Handler,
			ErrorLog:          options.ErrorLog,
			ReadHeaderTimeout: options.ReadHeaderTimeout,
			ReadTimeout:       options.ReadTimeout,
			WriteTimeout:      options.WriteTimeout,
			IdleTimeout:       options.IdleTimeout,
			MaxHeaderBytes:    1 << 20,
		},
		clock: options.Clock, observer: options.Observer,
		shutdownTimeout: options.ShutdownTimeout, shutdownDone: make(chan struct{}),
	}, nil
}

func (s *Server) emit(code ops.Code, outcome ops.Outcome) {
	event := ops.Event{
		Code: code, Operation: ops.OperationHTTP, Outcome: outcome,
		Severity: ops.SeverityInfo, At: s.clock.Now(),
	}
	if event.Validate() == nil {
		s.observer.Observe(context.Background(), event)
	}
}

func (s *Server) Serve(listener net.Listener) error {
	if s == nil || listener == nil {
		return ErrInvalidOptions
	}
	if !s.serving.CompareAndSwap(false, true) {
		return ErrAlreadyServing
	}
	s.emit(ops.CodeHTTPStarted, ops.OutcomeStarted)
	defer func() {
		s.emit(ops.CodeHTTPStopped, ops.OutcomeStopped)
		s.serving.Store(false)
	}()
	if err := s.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return ErrServe
	}
	return nil
}

func (s *Server) setShutdownError(err error) {
	s.shutdownMu.Lock()
	s.shutdownErr = err
	s.shutdownMu.Unlock()
}

func (s *Server) getShutdownError() error {
	s.shutdownMu.Lock()
	defer s.shutdownMu.Unlock()
	return s.shutdownErr
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrInvalidOptions
	}
	s.shutdownOnce.Do(func() {
		defer close(s.shutdownDone)
		shutdownContext, cancel := context.WithTimeout(ctx, s.shutdownTimeout)
		defer cancel()
		err := s.httpServer.Shutdown(shutdownContext)
		if err == nil {
			s.setShutdownError(nil)
			return
		}
		_ = s.httpServer.Close()
		if errors.Is(err, context.DeadlineExceeded) {
			s.setShutdownError(ErrShutdownTimeout)
			return
		}
		s.setShutdownError(ErrShutdown)
	})
	<-s.shutdownDone
	return s.getShutdownError()
}
