package daemon

import (
	"log/slog"
	"net/http"
)

func operationName(path string) string {
	switch path {
	case "/auth/register/begin":
		return "auth.register.begin"
	case "/auth/register/finish":
		return "auth.register.finish"
	case "/auth/login/begin":
		return "auth.login.begin"
	case "/auth/login/finish":
		return "auth.login.finish"
	case "/auth/native/begin":
		return "auth.native.begin"
	case "/auth/native/finish":
		return "auth.native.finish"
	case "/auth/logout", "/native/logout":
		return "auth.logout"
	case "/auth/native/info", "/native/login/start", "/native/login/poll", "/native/ticket":
		return "auth.native.control"
	case "/endpoint", "/cookie":
		return "relay.discovery"
	case "/", "/login", "/enroll", "/approve":
		return "web.page"
	case "/assets/auth.js", "/assets/style.css", "/assets/close.js":
		return "web.asset"
	default:
		return "http.not_found"
	}
}

type observedResponse struct {
	http.ResponseWriter
	status int
}

// WriteHeader records the first HTTP status.
func (w *observedResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *observedResponse) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

func (a *App) observeHTTP(w http.ResponseWriter, r *http.Request) {
	name := operationName(r.URL.Path)
	ctx, operation := a.observer.Start(r.Context(), name)
	response := &observedResponse{ResponseWriter: w}
	outcome := "error"
	defer func() {
		operation.End(ctx, outcome)
		a.logger.DebugContext(ctx, "HTTP operation complete", slog.String("operation", name), slog.String("outcome", outcome))
	}()
	a.serveHTTP(response, r.WithContext(ctx))
	switch {
	case response.status >= 500:
		outcome = "error"
	case response.status >= 400:
		outcome = "denied"
	default:
		outcome = "ok"
	}
}
