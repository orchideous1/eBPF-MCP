package server

import (
	"context"
	"errors"
	"fmt"

	"ebpf-mcp/internal/probes"
)

// ProbeServices adapts probe controller operations to server contracts.
type ProbeServices struct {
	executor       ObserveExecutor
	customizer     ProbeCustomizer
	loadAuthorizer LoadAuthorizer
}

// NewProbeServices creates a contract adapter around probe Controller.
func NewProbeServices(controller *probes.Controller) (*ProbeServices, error) {
	if controller == nil {
		return nil, fmt.Errorf("controller is nil")
	}
	return NewProbeServicesWithExecutorAndCustomizer(
		NewControllerObserveExecutor(controller),
		NewControllerProbeCustomizer(controller),
		AllowAllLoadAuthorizer{},
	)
}

// NewProbeServicesWithExecutor creates a contract adapter with pluggable execution and authorization.
func NewProbeServicesWithExecutor(executor ObserveExecutor, authorizer LoadAuthorizer) (*ProbeServices, error) {
	return NewProbeServicesWithExecutorAndCustomizer(executor, nil, authorizer)
}

// NewProbeServicesWithExecutorAndCustomizer creates a contract adapter with pluggable execution, update and authorization.
func NewProbeServicesWithExecutorAndCustomizer(executor ObserveExecutor, customizer ProbeCustomizer, authorizer LoadAuthorizer) (*ProbeServices, error) {
	if executor == nil {
		return nil, fmt.Errorf("executor is nil")
	}
	if authorizer == nil {
		authorizer = AllowAllLoadAuthorizer{}
	}
	return &ProbeServices{executor: executor, customizer: customizer, loadAuthorizer: authorizer}, nil
}

// Customize applies runtime probe updates.
func (s *ProbeServices) Customize(ctx context.Context, req CustomizeRequest) (CustomizeResult, error) {
	if req.Name == "" {
		return CustomizeResult{}, NewDomainError(ErrorInvalidArgument, "name is required")
	}
	if req.Params == nil {
		return CustomizeResult{}, NewDomainError(ErrorInvalidArgument, "params is required")
	}
	if req.DryRun {
		return CustomizeResult{Accepted: true, Reason: "dry run", NewState: "unchanged"}, nil
	}
	if s.customizer == nil {
		return CustomizeResult{}, NewDomainError(ErrorPermissionDenied, "probe customization is disabled")
	}

	status, err := s.customizer.Update(ctx, req.Name, req.Params)
	if err != nil {
		return CustomizeResult{}, mapProbeControlError(err)
	}

	return CustomizeResult{Accepted: true, NewState: status.State}, nil
}

// Control executes load, unload and status operations.
func (s *ProbeServices) Control(ctx context.Context, req ObserveRequest) (ObserveResult, error) {
	if req.ProbeName == "" {
		return ObserveResult{}, NewDomainError(ErrorInvalidArgument, "probeName is required")
	}

	switch req.Operation {
	case "load":
		if err := s.loadAuthorizer.AuthorizeLoad(ctx, req.ProbeName); err != nil {
			return ObserveResult{State: "denied", Admission: "denied", Reason: err.Error()}, NewDomainError(ErrorPermissionDenied, err.Error())
		}
		status, err := s.executor.Load(ctx, req.ProbeName)
		if err != nil {
			return ObserveResult{}, mapProbeControlError(err)
		}
		return ObserveResult{State: status.State, Admission: "allowed"}, nil
	case "unload":
		status, err := s.executor.Unload(ctx, req.ProbeName)
		if err != nil {
			return ObserveResult{}, mapProbeControlError(err)
		}
		return ObserveResult{State: status.State, Admission: "allowed"}, nil
	case "status":
		status, err := s.executor.Status(ctx, req.ProbeName)
		if err != nil {
			return ObserveResult{}, mapProbeControlError(err)
		}
		report := map[string]any{"loaded": status.Loaded}
		if status.LastError != "" {
			report["lastError"] = status.LastError
		}
		return ObserveResult{State: status.State, Admission: "allowed", QuotaReport: report}, nil
	default:
		return ObserveResult{}, NewDomainError(ErrorInvalidArgument, "operation must be one of load|unload|status")
	}
}

func mapProbeControlError(err error) error {
	if err == nil {
		return nil
	}
	var execErr *ExecutorError
	if errors.As(err, &execErr) {
		switch execErr.Code {
		case ExecutorErrProbeNotFound:
			return NewDomainError(ErrorProbeNotFound, execErr.Message)
		case ExecutorErrAlreadyLoaded, ExecutorErrNotLoaded:
			return NewDomainError(ErrorConflict, execErr.Message)
		default:
			return NewDomainError(ErrorRuntimeFailure, execErr.Message)
		}
	}
	if errors.Is(err, probes.ErrProbeNotFound) {
		return NewDomainError(ErrorProbeNotFound, err.Error())
	}
	if errors.Is(err, probes.ErrProbeAlreadyLoaded) || errors.Is(err, probes.ErrProbeNotLoaded) {
		return NewDomainError(ErrorConflict, err.Error())
	}
	return NewDomainError(ErrorRuntimeFailure, err.Error())
}
