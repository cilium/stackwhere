package main

import (
	"bytes"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartupURL(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{
			name: "host omitted",
			addr: ":8080",
			want: "http://127.0.0.1:8080",
		},
		{
			name: "explicit ipv4 host",
			addr: "0.0.0.0:8080",
			want: "http://0.0.0.0:8080",
		},
		{
			name: "explicit hostname",
			addr: "localhost:9090",
			want: "http://localhost:9090",
		},
		{
			name: "explicit ipv6 host",
			addr: "[::1]:8080",
			want: "http://[::1]:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := startupURL(tt.addr); got != tt.want {
				t.Fatalf("startupURL(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestWebCommandRequiresCollectionArg(t *testing.T) {
	cmd := root()
	cmd.SetArgs([]string{"web"})

	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected web command to fail when collection argument is missing")
	}
}

func TestWebCommandDoesNotAnnounceFailedBind(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve test address: %v", err)
	}
	defer func() {
		_ = listener.Close()
	}()

	cmd := root()
	cmd.SetArgs([]string{"web", "../../testdata/basic.o", "--addr", listener.Addr().String()})

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected web command to fail when address is already in use")
	}
	if got := stdout.String(); strings.Contains(got, "Serving stackwhere web UI") {
		t.Fatalf("web command announced a server that failed to start: %q", got)
	}
}

func TestWebHandlerServesLandingPage(t *testing.T) {
	app, err := newWebApp("../../testdata/basic.o", nil)
	if err != nil {
		t.Fatalf("failed to initialize web app: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	app.handler().ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("unexpected status code: got %d want 200", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "cil_entry") {
		t.Fatalf("expected landing page to include program name, got %q", body)
	}
	if !strings.Contains(body, "56 bytes") {
		t.Fatalf("expected landing page to include stack usage, got %q", body)
	}
}

func TestWebHandlerIncludesInstructionOnlyStackUsage(t *testing.T) {
	app, err := newWebApp("../../testdata/noinline.o", nil)
	if err != nil {
		t.Fatalf("failed to initialize web app: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	app.handler().ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("unexpected status code: got %d want 200", rr.Code)
	}
	if body := rr.Body.String(); !strings.Contains(body, "8 bytes") {
		t.Fatalf("expected instruction-derived stack usage in landing page, got %q", body)
	}
}

func TestWebHandlerServesProgramPage(t *testing.T) {
	app, err := newWebApp("../../testdata/basic.o", nil)
	if err != nil {
		t.Fatalf("failed to initialize web app: %v", err)
	}

	req := httptest.NewRequest("GET", "/program/cil_entry", nil)
	rr := httptest.NewRecorder()
	app.handler().ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("unexpected status code: got %d want 200", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "R10-0") {
		t.Fatalf("expected program page to include stack offset group, got %q", body)
	}
	if !strings.Contains(body, "a") {
		t.Fatalf("expected program page to include variable rows, got %q", body)
	}
	if !strings.Contains(body, "/source?file=") {
		t.Fatalf("expected program page to include source location links, got %q", body)
	}
	if !strings.Contains(body, "Instructions") {
		t.Fatalf("expected program page to include instructions pane, got %q", body)
	}
	if !strings.Contains(body, "Variable Lifetimes") {
		t.Fatalf("expected program page to include lifetimes pane, got %q", body)
	}
	if !strings.Contains(body, "<svg") {
		t.Fatalf("expected program page to include rendered lifetimes svg, got %q", body)
	}
	if !strings.Contains(body, "instruction-line") {
		t.Fatalf("expected program page to include interactive instruction lines, got %q", body)
	}
	if !strings.Contains(body, "data-raw=") {
		t.Fatalf("expected program page to include raw-offset markers for instruction lines, got %q", body)
	}
	if !strings.Contains(body, "instruction-comment-link") {
		t.Fatalf("expected program page to include linked instruction comments, got %q", body)
	}
}

func TestWebHandlerServesSourcePage(t *testing.T) {
	app, err := newWebApp("../../testdata/basic.o", nil)
	if err != nil {
		t.Fatalf("failed to initialize web app: %v", err)
	}

	req := httptest.NewRequest("GET", "/source?file=basic.c&line=62", nil)
	rr := httptest.NewRecorder()
	app.handler().ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("unexpected status code: got %d want 200", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "cil_entry") {
		t.Fatalf("expected source page to include C source content, got %q", body)
	}
	if !strings.Contains(body, "source-line-highlight") {
		t.Fatalf("expected source page to highlight requested line, got %q", body)
	}
}

func TestWebHandlerSourcePageNotFound(t *testing.T) {
	app, err := newWebApp("../../testdata/basic.o", nil)
	if err != nil {
		t.Fatalf("failed to initialize web app: %v", err)
	}

	req := httptest.NewRequest("GET", "/source?file=missing.c", nil)
	rr := httptest.NewRecorder()
	app.handler().ServeHTTP(rr, req)

	if rr.Code != 404 {
		t.Fatalf("unexpected status code: got %d want 404", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Source file not found") {
		t.Fatalf("expected friendly source not found message, got %q", body)
	}
}

func TestWebHandlerServesEmbeddedStaticAsset(t *testing.T) {
	app, err := newWebApp("../../testdata/basic.o", nil)
	if err != nil {
		t.Fatalf("failed to initialize web app: %v", err)
	}

	req := httptest.NewRequest("GET", "/static/style.css", nil)
	rr := httptest.NewRecorder()
	app.handler().ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("unexpected status code: got %d want 200", rr.Code)
	}

	if !strings.Contains(rr.Body.String(), "--bg:") {
		t.Fatalf("expected css asset content, got %q", rr.Body.String())
	}
}

func TestWebHandlerRejectsUnsupportedSourceType(t *testing.T) {
	app, err := newWebApp("../../testdata/basic.o", nil)
	if err != nil {
		t.Fatalf("failed to initialize web app: %v", err)
	}

	req := httptest.NewRequest("GET", "/source?file=go.mod", nil)
	rr := httptest.NewRecorder()
	app.handler().ServeHTTP(rr, req)

	if rr.Code != 400 {
		t.Fatalf("unexpected status code: got %d want 400", rr.Code)
	}
}

func TestWebHandlerRejectsSourceTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	allowedDir := filepath.Join(tmpDir, "allowed")
	if err := os.Mkdir(allowedDir, 0o755); err != nil {
		t.Fatalf("failed to create allowed source dir: %v", err)
	}

	outsideFile := filepath.Join(tmpDir, "outside.c")
	if err := os.WriteFile(outsideFile, []byte("int main(void) { return 0; }\n"), 0o644); err != nil {
		t.Fatalf("failed to create source file outside allowlist: %v", err)
	}

	app, err := newWebApp("../../testdata/basic.o", []string{allowedDir})
	if err != nil {
		t.Fatalf("failed to initialize web app: %v", err)
	}

	req := httptest.NewRequest("GET", "/source?file=../outside.c", nil)
	rr := httptest.NewRecorder()
	app.handler().ServeHTTP(rr, req)

	if rr.Code != 404 {
		t.Fatalf("unexpected status code: got %d want 404", rr.Code)
	}
}

func TestWebHandlerRejectsAbsolutePathOutsideSourceDir(t *testing.T) {
	tmpDir := t.TempDir()
	allowedDir := filepath.Join(tmpDir, "allowed")
	if err := os.Mkdir(allowedDir, 0o755); err != nil {
		t.Fatalf("failed to create allowed source dir: %v", err)
	}

	outsideFile := filepath.Join(tmpDir, "outside.c")
	if err := os.WriteFile(outsideFile, []byte("int main(void) { return 0; }\n"), 0o644); err != nil {
		t.Fatalf("failed to create source file outside allowlist: %v", err)
	}

	app, err := newWebApp("../../testdata/basic.o", []string{allowedDir})
	if err != nil {
		t.Fatalf("failed to initialize web app: %v", err)
	}

	req := httptest.NewRequest("GET", "/source?file="+outsideFile, nil)
	rr := httptest.NewRecorder()
	app.handler().ServeHTTP(rr, req)

	if rr.Code != 404 {
		t.Fatalf("unexpected status code: got %d want 404", rr.Code)
	}
}

func TestReadSourceLinesTruncatesByBytes(t *testing.T) {
	tmpDir := t.TempDir()
	sourcePath := filepath.Join(tmpDir, "large.c")

	line := []byte("int x = 1;\n")
	lineCount := (maxSourceBytes / len(line)) + 100
	content := bytes.Repeat(line, lineCount)
	if err := os.WriteFile(sourcePath, content, 0o644); err != nil {
		t.Fatalf("failed to write source file: %v", err)
	}

	lines, truncated, err := readSourceLines(sourcePath, 0)
	if err != nil {
		t.Fatalf("readSourceLines failed: %v", err)
	}
	if !truncated {
		t.Fatalf("expected truncated preview for file larger than maxSourceBytes")
	}
	if len(lines) >= lineCount {
		t.Fatalf("expected fewer preview lines than full file, got %d lines out of %d", len(lines), lineCount)
	}
}
