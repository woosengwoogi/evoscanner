package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/evoscanner/evoscanner/internal/crawler"
	"github.com/evoscanner/evoscanner/internal/plugins"
	"github.com/evoscanner/evoscanner/internal/scanner"
	"github.com/evoscanner/evoscanner/pkg/httpclient"
	"github.com/evoscanner/evoscanner/pkg/types"
)

// Server provides REST API and web dashboard.
type Server struct {
	httpServer *http.Server
	scanStore  *ScanStore
	config     *ServerConfig
}

// ServerConfig holds server configuration.
type ServerConfig struct {
	Host      string
	Port      int
	ScanStore string
}

// ScanStore manages scan results.
type ScanStore struct {
	mu      sync.RWMutex
	scans   map[string]*types.ScanResult
	results map[string][]types.Finding
}

func NewScanStore() *ScanStore {
	return &ScanStore{
		scans:   make(map[string]*types.ScanResult),
		results: make(map[string][]types.Finding),
	}
}

// ScanSummary is the API response for scan list.
type ScanSummary struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Status    string    `json:"status"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Findings  int       `json:"findings"`
	Endpoints int       `json:"endpoints"`
}

// New creates a new Server.
func New(cfg *ServerConfig) *Server {
	return &Server{
		scanStore: NewScanStore(),
		config:    cfg,
	}
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/scans", s.handleScans)
	mux.HandleFunc("/api/scans/", s.handleScanDetail)
	mux.HandleFunc("/api/scan", s.handleStartScan)
	mux.HandleFunc("/", s.handleDashboard)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 300 * time.Second, // Longer for scan uploads
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("port %d already in use or not available: %w", s.config.Port, err)
	}
	ln.Close()

	go func() {
		log.Printf("[*] Server starting on http://%s", addr)
		log.Printf("[*] Dashboard: http://%s/", addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[!] Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	log.Println("[*] Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	s.scanStore.mu.RLock()
	defer s.scanStore.mu.RUnlock()

	var summaries []ScanSummary
	for id, result := range s.scanStore.scans {
		findings := s.scanStore.results[id]
		status := "running"
		if !result.EndTime.IsZero() {
			status = "completed"
		}
		summaries = append(summaries, ScanSummary{
			ID:        id,
			Target:    result.Target,
			Status:    status,
			StartTime: result.StartTime,
			EndTime:   result.EndTime,
			Findings:  len(findings),
			Endpoints: result.Summary.TotalChecks,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"scans": summaries,
		"total": len(summaries),
	})
}

func (s *Server) handleScanDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := filepath.Base(r.URL.Path)
	if id == "scans" {
		http.NotFound(w, r)
		return
	}

	s.scanStore.mu.RLock()
	result, ok := s.scanStore.scans[id]
	findings := s.scanStore.results[id]
	s.scanStore.mu.RUnlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan":     result,
		"findings": findings,
	})
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var req struct {
		TargetURL string `json:"target_url"`
		Threads   int    `json:"threads"`
		MaxDepth  int    `json:"max_depth"`
		Timeout   string `json:"timeout"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.TargetURL == "" {
		http.Error(w, "target_url is required", http.StatusBadRequest)
		return
	}

	if req.Threads <= 0 {
		req.Threads = 10
	}
	if req.MaxDepth <= 0 {
		req.MaxDepth = 3
	}
	if req.Timeout == "" {
		req.Timeout = "30s"
	}

	timeout, _ := time.ParseDuration(req.Timeout)
	scanID := fmt.Sprintf("scan-%d", time.Now().UnixNano())

	// Create scan result
	result := &types.ScanResult{
		Target:    req.TargetURL,
		StartTime: time.Now(),
		Findings:  []types.Finding{},
		Summary: types.Summary{
			BySeverity: make(map[string]int),
			ByPlugin:   make(map[string]int),
		},
	}

	s.scanStore.mu.Lock()
	s.scanStore.scans[scanID] = result
	s.scanStore.results[scanID] = []types.Finding{}
	s.scanStore.mu.Unlock()

	// Run actual scan in background
	go func() {
		s.runScan(scanID, req.TargetURL, req.Threads, req.MaxDepth, timeout)
	}()

	json.NewEncoder(w).Encode(map[string]string{
		"id":      scanID,
		"status":  "started",
		"message": "Scan started successfully",
	})
}

// runScan executes the actual vulnerability scan
func (s *Server) runScan(scanID, targetURL string, threads, maxDepth int, timeout time.Duration) {
	log.Printf("[*] Starting scan %s for %s", scanID, targetURL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Build scan config
	config := &types.ScanConfig{
		TargetURL:   targetURL,
		Threads:     threads,
		Timeout:     timeout,
		MaxDepth:    maxDepth,
		MaxRequests: 1000,
		UserAgent:   "EvoScanner/1.0 (Server)",
		Verbose:     false,
	}

	// Create HTTP client
	httpClient := httpclient.New(config)

	// Create registry and register plugins
	registry := scanner.NewRegistry()
	plugins.RegisterAll(registry)

	// Phase 1: Crawl
	log.Printf("[*] [%s] Crawling target...", scanID)
	c := crawler.New(httpClient, config)
	target, err := c.Crawl(ctx, targetURL)
	if err != nil {
		log.Printf("[!] [%s] Crawl error: %v", scanID, err)
		s.updateScanStatus(scanID, "failed")
		return
	}

	log.Printf("[*] [%s] Discovered %d endpoints", scanID, len(target.Endpoints))

	// Phase 2: Scan
	log.Printf("[*] [%s] Running vulnerability scan...", scanID)
	engine := scanner.NewEngine(config, registry, httpClient)

	scanResult, err := engine.Scan(ctx, target)
	if err != nil {
		log.Printf("[!] [%s] Scan error: %v", scanID, err)
		s.updateScanStatus(scanID, "failed")
		return
	}

	allFindings := scanResult.Findings

	// Update summary
	s.scanStore.mu.Lock()
	if result, ok := s.scanStore.scans[scanID]; ok {
		result.Summary.TotalChecks = len(target.Endpoints)
		result.Summary.TotalFindings = len(allFindings)

		for _, f := range allFindings {
			sev := string(f.Severity)
			result.Summary.BySeverity[sev]++
			result.Summary.ByPlugin[f.PluginID]++
		}
	}
	s.scanStore.results[scanID] = allFindings
	s.scanStore.mu.Unlock()

	log.Printf("[*] [%s] Scan completed: %d findings", scanID, len(allFindings))
	s.updateScanStatus(scanID, "completed")
}

func (s *Server) updateScanStatus(scanID, status string) {
	s.scanStore.mu.Lock()
	defer s.scanStore.mu.Unlock()

	if result, ok := s.scanStore.scans[scanID]; ok {
		result.EndTime = time.Now()
		// Note: In a full implementation, we'd also update a Status field
		// For now, status is derived from EndTime.IsZero()
	}
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}

	content, contentType := getDashboardContent(path)
	w.Header().Set("Content-Type", contentType)
	w.Write(content)
}

func getDashboardContent(path string) ([]byte, string) {
	ext := strings.TrimPrefix(filepath.Ext(path), ".")

	switch ext {
	case "html", "":
		return []byte(dashboardHTML), "text/html; charset=utf-8"
	case "js":
		return []byte(dashboardJS), "application/javascript"
	case "css":
		return []byte(dashboardCSS), "text/css"
	default:
		return []byte(dashboardHTML), "text/html; charset=utf-8"
	}
}

func Config() *ServerConfig {
	host := getEnv("EVOSCANNER_HOST", "0.0.0.0")
	port := getEnvInt("EVOSCANNER_PORT", 8080)
	scanStore := getEnv("EVOSCANNER_SCAN_STORE", "./scans")

	return &ServerConfig{
		Host:      host,
		Port:      port,
		ScanStore: scanStore,
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			return parsed
		}
	}
	return def
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EvoScanner - Vulnerability Scanner</title>
    <link rel="stylesheet" href="/app.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>EvoScanner</h1>
            <p>Self-evolving Vulnerability Scanner</p>
        </header>

        <div class="actions">
            <button id="newScanBtn" class="btn btn-primary">+ New Scan</button>
        </div>

        <div id="scanForm" class="scan-form" style="display: none;">
            <h2>Start New Scan</h2>
            <form id="scanFormElement">
                <div class="form-group">
                    <label for="targetUrl">Target URL</label>
                    <input type="url" id="targetUrl" name="targetUrl" placeholder="https://example.com" required>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label for="threads">Threads</label>
                        <input type="number" id="threads" name="threads" value="10" min="1" max="100">
                    </div>
                    <div class="form-group">
                        <label for="maxDepth">Max Depth</label>
                        <input type="number" id="maxDepth" name="maxDepth" value="3" min="1" max="10">
                    </div>
                    <div class="form-group">
                        <label for="timeout">Timeout</label>
                        <select id="timeout" name="timeout">
                            <option value="10s">10s</option>
                            <option value="30s" selected>30s</option>
                            <option value="60s">60s</option>
                            <option value="120s">120s</option>
                        </select>
                    </div>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn btn-primary">Start Scan</button>
                    <button type="button" class="btn btn-secondary" id="cancelBtn">Cancel</button>
                </div>
            </form>
        </div>

        <div class="scans-section">
            <h2>Scan History</h2>
            <div id="scansList" class="scans-list">
                <p class="loading">Loading...</p>
            </div>
        </div>

        <div id="scanDetail" class="scan-detail" style="display: none;">
            <div class="detail-header">
                <h2 id="detailTitle">Scan Details</h2>
                <button class="btn btn-secondary" id="closeDetail">Close</button>
            </div>
            <div id="detailContent"></div>
        </div>
    </div>

    <script src="/app.js"></script>
</body>
</html>`

const dashboardJS = `var API_BASE = '/api';
var scans = [];
var currentScan = null;

function fetchScans() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', API_BASE + '/scans', true);
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            if (xhr.status === 200) {
                var data = JSON.parse(xhr.responseText);
                scans = data.scans || [];
                renderScans();
            } else {
                document.getElementById('scansList').innerHTML = '<p class="error">Failed to load scans</p>';
            }
        }
    };
    xhr.send();
}

function renderScans() {
    var container = document.getElementById('scansList');
    if (scans.length === 0) {
        container.innerHTML = '<p class="empty">No scans yet. Start a new scan!</p>';
        return;
    }
    var html = '';
    for (var i = 0; i < scans.length; i++) {
        var scan = scans[i];
        html += '<div class="scan-item" data-id="' + scan.id + '">' +
            '<div class="scan-info">' +
                '<span class="scan-target">' + escapeHtml(scan.target) + '</span>' +
                '<span class="scan-time">' + formatTime(scan.start_time) + '</span>' +
            '</div>' +
            '<div class="scan-status ' + scan.status + '">' + scan.status + '</div>' +
            '<div class="scan-stats">' +
                '<span>' + scan.findings + ' findings</span>' +
                '<span>' + scan.endpoints + ' endpoints</span>' +
            '</div>' +
        '</div>';
    }
    container.innerHTML = html;
    var items = container.querySelectorAll('.scan-item');
    for (var j = 0; j < items.length; j++) {
        items[j].addEventListener('click', function() {
            showScanDetail(this.getAttribute('data-id'));
        });
    }
}

function showScanDetail(id) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', API_BASE + '/scans/' + id, true);
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4 && xhr.status === 200) {
            var data = JSON.parse(xhr.responseText);
            currentScan = data;
            document.getElementById('scanDetail').style.display = 'block';
            document.getElementById('detailTitle').textContent = 'Scan: ' + data.scan.target;
            var findings = data.findings || [];
            var detailContent = document.getElementById('detailContent');
            if (findings.length === 0) {
                detailContent.innerHTML = '<p class="empty">No vulnerabilities found</p>';
            } else {
                var findingsHtml = '';
                for (var k = 0; k < findings.length; k++) {
                    var f = findings[k];
                    findingsHtml += '<div class="finding-item">' +
                        '<span class="severity ' + (f.severity || 'info') + '">' + (f.severity || 'info') + '</span>' +
                        '<span class="plugin">' + f.plugin_id + '</span>' +
                        '<span class="url">' + escapeHtml(f.url) + '</span>' +
                    '</div>';
                }
                detailContent.innerHTML = findingsHtml;
            }
            document.getElementById('scanDetail').scrollIntoView({ behavior: 'smooth' });
        }
    };
    xhr.send();
}

function escapeHtml(text) {
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTime(t) {
    if (!t) return '-';
    return new Date(t).toLocaleString();
}

document.getElementById('newScanBtn').addEventListener('click', function() {
    document.getElementById('scanForm').style.display = 'block';
    document.getElementById('targetUrl').focus();
});

document.getElementById('cancelBtn').addEventListener('click', function() {
    document.getElementById('scanForm').style.display = 'none';
});

document.getElementById('scanFormElement').addEventListener('submit', function(e) {
    e.preventDefault();
    var targetUrl = document.getElementById('targetUrl').value;
    var threads = parseInt(document.getElementById('threads').value);
    var maxDepth = parseInt(document.getElementById('maxDepth').value);
    var timeout = document.getElementById('timeout').value;
    
    var xhr = new XMLHttpRequest();
    xhr.open('POST', API_BASE + '/scan', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4 && xhr.status === 200) {
            var data = JSON.parse(xhr.responseText);
            if (data.id) {
                document.getElementById('scanForm').style.display = 'none';
                document.getElementById('scanFormElement').reset();
                fetchScans();
            }
        }
    };
    xhr.send(JSON.stringify({ target_url: targetUrl, threads: threads, max_depth: maxDepth, timeout: timeout }));
});

document.getElementById('closeDetail').addEventListener('click', function() {
    document.getElementById('scanDetail').style.display = 'none';
});

fetchScans();
setInterval(fetchScans, 10000);
`

const dashboardCSS = `* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; min-height: 100vh; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
header { text-align: center; padding: 40px 0; border-bottom: 1px solid #30363d; margin-bottom: 30px; }
header h1 { font-size: 2.5rem; margin-bottom: 10px; }
header p { color: #8b949e; }
.actions { margin-bottom: 20px; }
.btn { padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 1rem; transition: all 0.2s; }
.btn-primary { background: #238636; color: white; }
.btn-primary:hover { background: #2ea043; }
.btn-secondary { background: #30363d; color: #c9d1d9; }
.btn-secondary:hover { background: #484f58; }
.scan-form { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 30px; }
.scan-form h2 { margin-bottom: 20px; }
.form-group { margin-bottom: 15px; }
.form-group label { display: block; margin-bottom: 5px; color: #8b949e; }
.form-group input, .form-group select { width: 100%; padding: 10px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 1rem; }
.form-row { display: flex; gap: 15px; }
.form-row .form-group { flex: 1; }
.form-actions { display: flex; gap: 10px; margin-top: 20px; }
.scans-section h2 { margin-bottom: 20px; }
.scans-list { display: flex; flex-direction: column; gap: 10px; }
.scan-item { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px 20px; cursor: pointer; transition: all 0.2s; }
.scan-item:hover { border-color: #58a6ff; transform: translateY(-2px); }
.scan-info { display: flex; justify-content: space-between; margin-bottom: 10px; }
.scan-target { font-weight: bold; color: #58a6ff; }
.scan-time { color: #8b949e; font-size: 0.9rem; }
.scan-status { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: bold; margin-bottom: 10px; }
.scan-status.running { background: #1f6feb; color: white; }
.scan-status.completed { background: #238636; color: white; }
.scan-status.failed { background: #da3633; color: white; }
.scan-stats { display: flex; gap: 20px; color: #8b949e; font-size: 0.9rem; }
.scan-detail { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-top: 30px; }
.detail-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.finding-item { display: flex; align-items: center; gap: 15px; padding: 10px; border-bottom: 1px solid #30363d; }
.finding-item:last-child { border-bottom: none; }
.severity { padding: 3px 10px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
.severity.high { background: #da3633; color: white; }
.severity.medium { background: #d29922; color: black; }
.severity.low { background: #3fb950; color: white; }
.severity.info { background: #58a6ff; color: white; }
.plugin { font-weight: bold; color: #c9d1d9; }
.url { color: #8b949e; font-size: 0.9rem; word-break: break-all; }
.loading, .empty, .error { text-align: center; padding: 40px; color: #8b949e; }
.error { color: #da3633; }
`
