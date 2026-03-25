package server

// debugf prints debug logs only when debug mode is enabled.
func (s *Server) debugf(format string, args ...any) {
	if s == nil || !s.cfg.Debug || s.logger == nil {
		return
	}
	s.logger.Printf("[DEBUG] "+format, args...)
}

// infof prints informational logs for server lifecycle and key events.
func (s *Server) infof(format string, args ...any) {
	if s == nil || s.logger == nil {
		return
	}
	s.logger.Printf("[INFO] "+format, args...)
}
