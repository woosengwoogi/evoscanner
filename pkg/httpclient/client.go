// Package httpclient provides a configurable HTTP client with retry and connection pooling.
package httpclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/evoscanner/evoscanner/internal/scanner"
	"github.com/evoscanner/evoscanner/pkg/types"
)

// Client implements scanner.HttpClient with retry, proxy, and connection pooling.
type Client struct {
	httpClient *http.Client
	config     *types.ScanConfig
	maxRetries int

	// Latency tracking for adaptive thread adjustment
	recentLatencies []int64
	latencyMu       sync.Mutex
}

// New creates a new HTTP client from scan config.
func New(config *types.ScanConfig) *Client {
	// Dynamic connection pool based on threads and fast mode
	maxIdleConnsPerHost := 10
	maxIdleConns := 100

	if config.FastMode {
		maxIdleConnsPerHost = config.Threads * 2
		maxIdleConns = config.Threads * 4
		if maxIdleConnsPerHost > 200 {
			maxIdleConnsPerHost = 200
		}
		if maxIdleConns > 500 {
			maxIdleConns = 500
		}
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: maxIdleConnsPerHost,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.VerifySSL,
		},
	}

	// Proxy support
	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	redirectPolicy := func(req *http.Request, via []*http.Request) error {
		if !config.FollowRedirect {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}

	maxRetries := config.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}

	return &Client{
		httpClient: &http.Client{
			Timeout:       config.Timeout,
			Transport:     transport,
			CheckRedirect: redirectPolicy,
		},
		config:          config,
		maxRetries:      maxRetries,
		recentLatencies: make([]int64, 0, 20),
	}
}

// Do sends an HTTP request and returns the response.
func (c *Client) Do(ctx context.Context, req *scanner.Request) (*scanner.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		resp, err := c.doOnce(ctx, req)
		if err == nil {
			c.RecordLatency(resp.Latency)
			return resp, nil
		}
		lastErr = err

		// Don't retry on context cancellation
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// Brief backoff before retry (faster in fast mode)
		if attempt < c.maxRetries {
			backoffMs := 500
			if c.config.FastMode {
				backoffMs = 100
			}
			time.Sleep(time.Duration(backoffMs) * time.Millisecond)
		}
	}

	c.RecordLatency(c.config.Timeout.Milliseconds())

	return nil, fmt.Errorf("after %d retries: %w", c.maxRetries, lastErr)
}

func (c *Client) doOnce(ctx context.Context, req *scanner.Request) (*scanner.Response, error) {
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set default headers
	httpReq.Header.Set("User-Agent", c.config.UserAgent)

	// Set custom global headers
	for k, v := range c.config.Headers {
		httpReq.Header.Set(k, v)
	}

	// Set cookies
	if c.config.Cookies != "" {
		httpReq.Header.Set("Cookie", c.config.Cookies)
	}

	// Set per-request headers (override globals)
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Set Content-Type for POST with body
	if req.Body != "" && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Build raw request string for evidence
	rawReq := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n",
		httpReq.Method, httpReq.URL.RequestURI(), httpReq.URL.Host)
	for k, vals := range httpReq.Header {
		for _, v := range vals {
			rawReq += fmt.Sprintf("%s: %s\r\n", k, v)
		}
	}
	if req.Body != "" {
		rawReq += "\r\n" + req.Body
	}

	start := time.Now()
	resp, err := c.httpClient.Do(httpReq)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB max
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}

	// Build raw response header string
	rawResp := fmt.Sprintf("HTTP/%d.%d %s\r\n",
		resp.ProtoMajor, resp.ProtoMinor, resp.Status)
	for k, vals := range resp.Header {
		for _, v := range vals {
			rawResp += fmt.Sprintf("%s: %s\r\n", k, v)
		}
	}
	rawResp += "\r\n" + string(body)

	return &scanner.Response{
		StatusCode:  resp.StatusCode,
		Headers:     resp.Header,
		Body:        string(body),
		RawRequest:  rawReq,
		RawResponse: rawResp,
		Latency:     latency,
	}, nil
}

// RecordLatency records a response latency for adaptive thread adjustment.
func (c *Client) RecordLatency(latencyMs int64) {
	c.latencyMu.Lock()
	defer c.latencyMu.Unlock()

	c.recentLatencies = append(c.recentLatencies, latencyMs)
	if len(c.recentLatencies) > 20 {
		c.recentLatencies = c.recentLatencies[1:]
	}
}

// GetRecentLatency returns the average of recent latencies.
func (c *Client) GetRecentLatency() int64 {
	c.latencyMu.Lock()
	defer c.latencyMu.Unlock()

	if len(c.recentLatencies) == 0 {
		return 0
	}

	var sum int64
	for _, l := range c.recentLatencies {
		sum += l
	}
	return sum / int64(len(c.recentLatencies))
}
