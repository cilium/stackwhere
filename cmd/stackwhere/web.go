package main

import (
	"bufio"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/stackwhere/internal/stackview"
	"github.com/spf13/cobra"
)

//go:embed webassets/*
var webAssets embed.FS

type webCmd struct {
	flagAddr       *string
	flagSourceDirs *[]string
}

func webCommand() *cobra.Command {
	c := &cobra.Command{
		Use:     "web {collection}",
		Aliases: []string{"w"},
		Short:   "Hosts an interactive local web UI for stack usage.",
		Long:    "Hosts an interactive local web UI for stack usage from the given collection.",
		Example: "stackwhere web /path/to/collection.o --addr :8080",
		Args:    cobra.ExactArgs(1),
	}

	flags := c.Flags()
	wc := &webCmd{
		flagAddr: flags.String("addr", ":8080", "Address to bind the local web server to"),
		flagSourceDirs: flags.StringSlice(
			"source-dir",
			nil,
			"Directory allowed for source file lookups (repeatable)",
		),
	}

	c.RunE = wc.runE
	return c
}

func (wc *webCmd) runE(cmd *cobra.Command, args []string) error {
	collectionPath := args[0]

	app, err := newWebApp(collectionPath, *wc.flagSourceDirs)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", *wc.flagAddr)
	if err != nil {
		return fmt.Errorf("web server failed: %w", err)
	}
	defer func() {
		_ = listener.Close()
	}()

	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Serving stackwhere web UI on %s\n", startupURL(*wc.flagAddr)); err != nil {
		return err
	}

	server := &http.Server{
		Addr:    *wc.flagAddr,
		Handler: app.handler(),
	}

	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("web server failed: %w", err)
	}
	return nil
}

func startupURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}

	if host == "" {
		host = "127.0.0.1"
	}

	return "http://" + net.JoinHostPort(host, port)
}

type webProgram struct {
	Name       string
	URLName    string
	StackUsage int64
}

type webSlotEntry struct {
	Size        string
	Name        string
	FileLineCol string
	SourceURL   string
}

type webSlotGroup struct {
	Offset  int64
	Entries []webSlotEntry
}

type webProgramPage struct {
	Groups           []webSlotGroup
	InstructionLines []webInstructionLine
	LifetimesSVG     template.HTML
}

type webInstructionLine struct {
	Text          string
	RawOffset     int
	IsComment     bool
	SourceURL     string
	CommentIndent string
	CommentText   string
}

type webApp struct {
	programs      []webProgram
	programDetail map[string]webProgramPage
	indexTmpl     *template.Template
	programTmpl   *template.Template
	sourceTmpl    *template.Template
	staticFS      fs.FS
	sourceDirs    []string
}

type sourceLine struct {
	Number      int
	Content     string
	IsHighlight bool
}

const (
	maxSourceLines = 20000
	maxSourceBytes = 2 << 20
)

var errSourceFileFound = errors.New("source file found")

func newWebApp(collectionPath string, sourceDirs []string) (*webApp, error) {
	analyzer, err := stackview.NewAnalyzer(collectionPath)
	if err != nil {
		return nil, err
	}

	normalizedSourceDirs, err := normalizeSourceDirs(collectionPath, sourceDirs)
	if err != nil {
		return nil, err
	}

	summary, err := analyzer.CollectionSummaryInCollection()
	if err != nil {
		return nil, err
	}
	spec, functions, err := loadCollectionFunctions(collectionPath)
	if err != nil {
		return nil, err
	}

	programs := make([]webProgram, 0, len(summary))
	programDetail := make(map[string]webProgramPage, len(summary))

	for _, prog := range summary {
		slots, err := analyzer.ProgramDetails(prog.Name)
		if err != nil {
			if errors.Is(err, stackview.ErrFunctionNotFoundInCollection) {
				continue
			}
			return nil, err
		}

		fn, ok := functions[prog.Name]
		if !ok || fn.fn == nil {
			continue
		}

		graph, err := buildProgramLifetimeGraph(spec, fn.insns, false)
		if err != nil {
			return nil, err
		}

		programDetail[prog.Name] = webProgramPage{
			Groups:           toWebSlotGroups(slots),
			InstructionLines: toWebInstructionLines(fn.insns),
			LifetimesSVG:     template.HTML(graph),
		}

		programs = append(programs, webProgram{
			Name:       prog.Name,
			URLName:    url.PathEscape(prog.Name),
			StackUsage: prog.StackUsage,
		})
	}

	indexTmpl, err := template.ParseFS(webAssets, "webassets/index.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse index template: %w", err)
	}

	programTmpl, err := template.ParseFS(webAssets, "webassets/program.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse program template: %w", err)
	}

	sourceTmpl, err := template.ParseFS(webAssets, "webassets/source.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse source template: %w", err)
	}

	staticFS, err := fs.Sub(webAssets, "webassets")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize static assets: %w", err)
	}

	return &webApp{
		programs:      programs,
		programDetail: programDetail,
		indexTmpl:     indexTmpl,
		programTmpl:   programTmpl,
		sourceTmpl:    sourceTmpl,
		staticFS:      staticFS,
		sourceDirs:    normalizedSourceDirs,
	}, nil
}

func normalizeSourceDirs(collectionPath string, sourceDirs []string) ([]string, error) {
	if len(sourceDirs) == 0 {
		sourceDirs = []string{filepath.Dir(collectionPath)}
	}

	normalized := make([]string, 0, len(sourceDirs))
	seen := make(map[string]struct{}, len(sourceDirs))

	for _, dir := range sourceDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}

		absDir, err := filepath.Abs(dir)
		if err != nil {
			return nil, fmt.Errorf("resolve source dir %q: %w", dir, err)
		}

		realDir, err := filepath.EvalSymlinks(absDir)
		if err != nil {
			return nil, fmt.Errorf("resolve source dir %q: %w", dir, err)
		}

		info, err := os.Stat(realDir)
		if err != nil {
			return nil, fmt.Errorf("stat source dir %q: %w", dir, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("source dir %q is not a directory", dir)
		}

		if _, ok := seen[realDir]; ok {
			continue
		}
		seen[realDir] = struct{}{}
		normalized = append(normalized, realDir)
	}

	if len(normalized) == 0 {
		return nil, errors.New("at least one source directory must be configured")
	}

	return normalized, nil
}

func toWebSlotGroups(slots [][]stackview.SlotUsage) []webSlotGroup {
	groups := make([]webSlotGroup, 0, len(slots))
	for _, group := range slots {
		displaySlots := slices.CompactFunc(slices.Clone(group), func(a, b stackview.SlotUsage) bool {
			return a.DisplayEqual(b)
		})

		entries := make([]webSlotEntry, 0, len(displaySlots))
		for _, slot := range displaySlots {
			size := fmt.Sprintf("%d", slot.ByteSize)
			if slot.ByteSize == -1 {
				size = "?"
			}

			name := slot.Name
			if name == "" {
				name = "(unknown)"
			}

			entries = append(entries, webSlotEntry{
				Size:        size,
				Name:        name,
				FileLineCol: slot.FileLineCol,
				SourceURL:   sourceURLForLocation(slot.FileLineCol),
			})
		}

		groups = append(groups, webSlotGroup{
			Offset:  group[0].Offset,
			Entries: entries,
		})
	}

	slices.Reverse(groups)

	return groups
}

func toWebInstructionLines(insns asm.Instructions) []webInstructionLine {
	rawOffsetSourceURL := make(map[int]string, len(insns))
	rawOffset := 0
	for _, ins := range insns {
		if src, ok := ins.Source().(*btf.Line); ok && src.LineNumber() != 0 {
			loc := fmt.Sprintf("%s:%d", src.FileName(), src.LineNumber())
			if sourceURL := sourceURLForLocation(loc); sourceURL != "" {
				rawOffsetSourceURL[rawOffset] = sourceURL
			}
		}

		rawOffset += int(ins.Size() / asm.InstructionSize)
	}

	raw := fmt.Sprintf("%+v", insns)
	lines := strings.Split(raw, "\n")
	out := make([]webInstructionLine, 0, len(lines))
	pendingCommentIdx := make([]int, 0, 4)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		isComment := strings.HasPrefix(trimmed, ";")
		rawOffset := -1
		if idx := strings.Index(line, ":"); idx > 0 {
			candidate := strings.TrimSpace(line[:idx])
			if n, err := strconv.Atoi(candidate); err == nil {
				rawOffset = n
			}
		}

		out = append(out, webInstructionLine{
			Text:      line,
			RawOffset: rawOffset,
			IsComment: isComment,
		})

		lineIdx := len(out) - 1
		if isComment {
			commentStart := strings.Index(line, ";")
			if commentStart >= 0 {
				out[lineIdx].CommentIndent = line[:commentStart]
				out[lineIdx].CommentText = line[commentStart:]
			} else {
				out[lineIdx].CommentText = line
			}
		}
		if isComment {
			pendingCommentIdx = append(pendingCommentIdx, lineIdx)
			continue
		}

		if rawOffset >= 0 {
			if sourceURL, found := rawOffsetSourceURL[rawOffset]; found {
				for _, idx := range pendingCommentIdx {
					out[idx].SourceURL = sourceURL
				}
			}
			pendingCommentIdx = pendingCommentIdx[:0]
		}
	}

	return out
}

func (wa *webApp) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(wa.staticFS))))
	mux.HandleFunc("/source", wa.handleSource)
	mux.HandleFunc("/", wa.handleIndex)
	mux.HandleFunc("/program/", wa.handleProgram)
	return mux
}

func (wa *webApp) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data := struct {
		Programs []webProgram
	}{Programs: wa.programs}

	if err := wa.indexTmpl.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to render page: %v", err), http.StatusInternalServerError)
		return
	}
}

func (wa *webApp) handleProgram(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/program/")
	if name == "" {
		http.NotFound(w, r)
		return
	}

	decodedName, err := url.PathUnescape(name)
	if err != nil {
		http.Error(w, "invalid program name", http.StatusBadRequest)
		return
	}

	detail, ok := wa.programDetail[decodedName]
	if !ok {
		http.NotFound(w, r)
		return
	}

	data := struct {
		ProgramName      string
		Groups           []webSlotGroup
		InstructionLines []webInstructionLine
		LifetimesSVG     template.HTML
	}{
		ProgramName:      decodedName,
		Groups:           detail.Groups,
		InstructionLines: detail.InstructionLines,
		LifetimesSVG:     detail.LifetimesSVG,
	}

	if err := wa.programTmpl.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to render page: %v", err), http.StatusInternalServerError)
		return
	}
}

func sourceURLForLocation(fileLineCol string) string {
	file, line, _ := parseLocation(fileLineCol)
	if file == "" || !isSupportedSourceFile(file) {
		return ""
	}

	v := url.Values{}
	v.Set("file", file)
	if line > 0 {
		v.Set("line", strconv.Itoa(line))
	}

	return "/source?" + v.Encode()
}

func parseLocation(fileLineCol string) (string, int, int) {
	parts := strings.Split(fileLineCol, ":")
	if len(parts) == 0 {
		return "", 0, 0
	}

	last, lastErr := strconv.Atoi(parts[len(parts)-1])
	if lastErr != nil {
		return fileLineCol, 0, 0
	}

	if len(parts) == 1 {
		return fileLineCol, 0, 0
	}

	secondLast, secondLastErr := strconv.Atoi(parts[len(parts)-2])
	if secondLastErr == nil {
		return strings.Join(parts[:len(parts)-2], ":"), secondLast, last
	}

	return strings.Join(parts[:len(parts)-1], ":"), last, 0
}

func isSupportedSourceFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".c" || ext == ".h"
}

func (wa *webApp) handleSource(w http.ResponseWriter, r *http.Request) {
	requestedFile := strings.TrimSpace(r.URL.Query().Get("file"))
	if requestedFile == "" {
		http.Error(w, "missing file query parameter", http.StatusBadRequest)
		return
	}
	if !isSupportedSourceFile(requestedFile) {
		http.Error(w, "unsupported source file type", http.StatusBadRequest)
		return
	}

	lineNumber := 0
	lineParam := strings.TrimSpace(r.URL.Query().Get("line"))
	if lineParam != "" {
		parsedLine, err := strconv.Atoi(lineParam)
		if err != nil || parsedLine < 1 {
			http.Error(w, "invalid line query parameter", http.StatusBadRequest)
			return
		}
		lineNumber = parsedLine
	}

	resolvedPath, ok := wa.resolveSourcePath(requestedFile)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_ = wa.sourceTmpl.Execute(w, struct {
			Found       bool
			RequestPath string
			SourceDirs  []string
		}{
			Found:       false,
			RequestPath: requestedFile,
			SourceDirs:  wa.sourceDirs,
		})
		return
	}

	lines, truncated, err := readSourceLines(resolvedPath, lineNumber)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read source file: %v", err), http.StatusInternalServerError)
		return
	}

	if err := wa.sourceTmpl.Execute(w, struct {
		Found        bool
		RequestPath  string
		ResolvedPath string
		Lines        []sourceLine
		Truncated    bool
		SourceDirs   []string
	}{
		Found:        true,
		RequestPath:  requestedFile,
		ResolvedPath: resolvedPath,
		Lines:        lines,
		Truncated:    truncated,
		SourceDirs:   wa.sourceDirs,
	}); err != nil {
		http.Error(w, fmt.Sprintf("failed to render page: %v", err), http.StatusInternalServerError)
		return
	}
}

func (wa *webApp) resolveSourcePath(requestedPath string) (string, bool) {
	cleanPath := filepath.Clean(requestedPath)
	if cleanPath == "." || cleanPath == "" {
		return "", false
	}
	if !isSupportedSourceFile(cleanPath) {
		return "", false
	}

	candidates := make([]string, 0, len(wa.sourceDirs))
	if filepath.IsAbs(cleanPath) {
		candidates = append(candidates, cleanPath)
	} else {
		for _, sourceDir := range wa.sourceDirs {
			candidates = append(candidates, filepath.Join(sourceDir, cleanPath))
		}
	}

	for _, candidate := range candidates {
		resolvedPath, ok := wa.resolveAllowedSourcePath(candidate)
		if ok {
			return resolvedPath, true
		}
	}

	baseName := filepath.Base(cleanPath)
	if baseName == "." || baseName == string(filepath.Separator) {
		return "", false
	}

	var foundPath string
	for _, sourceDir := range wa.sourceDirs {
		err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if d.Name() != baseName {
				return nil
			}
			resolvedPath, ok := wa.resolveAllowedSourcePath(path)
			if !ok {
				return nil
			}
			foundPath = resolvedPath
			return errSourceFileFound
		})
		if foundPath != "" {
			return foundPath, true
		}
		if err != nil && !errors.Is(err, errSourceFileFound) {
			return "", false
		}
	}

	return "", false
}

func (wa *webApp) resolveAllowedSourcePath(candidate string) (string, bool) {
	if !isReadableFile(candidate) {
		return "", false
	}

	absPath, err := filepath.Abs(candidate)
	if err != nil {
		return "", false
	}

	resolvedPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", false
	}

	if !isSupportedSourceFile(resolvedPath) {
		return "", false
	}

	for _, sourceDir := range wa.sourceDirs {
		if pathInDir(resolvedPath, sourceDir) {
			return resolvedPath, true
		}
	}

	return "", false
}

func pathInDir(path string, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func isReadableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

func readSourceLines(path string, highlightLine int) (lines []sourceLine, truncated bool, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	limitedReader := &io.LimitedReader{R: file, N: maxSourceBytes}
	reader := bufio.NewScanner(limitedReader)
	reader.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lines = make([]sourceLine, 0, 256)
	for reader.Scan() {
		if len(lines) >= maxSourceLines {
			return lines, true, nil
		}

		lineNumber := len(lines) + 1
		lines = append(lines, sourceLine{
			Number:      lineNumber,
			Content:     reader.Text(),
			IsHighlight: lineNumber == highlightLine,
		})
	}

	if err := reader.Err(); err != nil {
		return nil, false, err
	}

	if limitedReader.N == 0 {
		var nextByte [1]byte
		n, readErr := file.Read(nextByte[:])
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return nil, false, readErr
		}
		if n > 0 {
			return lines, true, nil
		}
	}

	return lines, false, nil
}
