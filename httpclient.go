package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultAcceptHTML = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
)

type NetClient struct {
	cookies          *CookieStore
	profile          BrowserProfile
	stdoutHeaders    bool
	primaryTransport *http.Transport
	http1Transport   *http.Transport
	client           *http.Client

	mu             sync.Mutex
	lastProto      string
	lastRemoteAddr string
}

func NewNetClient(cookies *CookieStore, profile BrowserProfile, stdoutHeaders bool) *NetClient {
	primary := &http.Transport{
		DialContext:           dialPreferIPv6,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	http1 := &http.Transport{
		DialContext:         dialPreferIPv6,
		ForceAttemptHTTP2:   false,
		DisableCompression:  true,
		TLSNextProto:        make(map[string]func(string, *tls.Conn) http.RoundTripper),
		TLSClientConfig:     &tls.Config{NextProtos: []string{"http/1.1"}},
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	nc := &NetClient{
		cookies:          cookies,
		profile:          profile,
		stdoutHeaders:    stdoutHeaders,
		primaryTransport: primary,
		http1Transport:   http1,
	}

	nc.client = &http.Client{
		Timeout: 30 * time.Second,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nc.roundTrip(req)
		}),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return nc
}

func (nc *NetClient) Close() {
	nc.primaryTransport.CloseIdleConnections()
	nc.http1Transport.CloseIdleConnections()
}

func (nc *NetClient) LastTransportInfo() (proto string, remoteAddr string) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	return nc.lastProto, nc.lastRemoteAddr
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// dialPreferIPv6 resolves DNS records and tries IPv6 addresses first,
// falling back to IPv4 if IPv6 is unreachable or fails.
func dialPreferIPv6(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		return d.DialContext(ctx, network, addr)
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	var v6, v4 []net.IPAddr
	for _, ip := range ips {
		if ip.IP.To4() == nil {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}

	var lastErr error
	for _, ip := range v6 {
		d := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
		target := net.JoinHostPort(ip.String(), port)
		conn, err := d.DialContext(ctx, "tcp6", target)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	for _, ip := range v4 {
		d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		target := net.JoinHostPort(ip.String(), port)
		conn, err := d.DialContext(ctx, "tcp4", target)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no IP addresses resolved for host %q", host)
}

func (nc *NetClient) roundTrip(req *http.Request) (*http.Response, error) {
	var remoteAddr string
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil && info.Conn.RemoteAddr() != nil {
				remoteAddr = info.Conn.RemoteAddr().String()
			}
		},
	}
	tracedReq := req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	if nc.stdoutHeaders {
		printRequestHeaders(tracedReq)
	}

	resp, err := nc.primaryTransport.RoundTrip(tracedReq)
	if err != nil && strings.EqualFold(tracedReq.URL.Scheme, "https") {
		// Fall back to HTTP/1.1 if the HTTP/2 attempt failed before receiving a response.
		retryReq := tracedReq.Clone(tracedReq.Context())
		if tracedReq.GetBody != nil {
			bodyCopy, bodyErr := tracedReq.GetBody()
			if bodyErr == nil {
				retryReq.Body = bodyCopy
			}
		}
		if retryResp, retryErr := nc.http1Transport.RoundTrip(retryReq); retryErr == nil {
			resp = retryResp
			err = nil
		}
	}
	if err != nil {
		return nil, err
	}

	nc.mu.Lock()
	nc.lastProto = resp.Proto
	if remoteAddr != "" {
		nc.lastRemoteAddr = remoteAddr
	}
	nc.mu.Unlock()

	if nc.stdoutHeaders {
		printResponseHeaders(resp)
	}

	return resp, nil
}

func printRequestHeaders(req *http.Request) {
	ts := time.Now().Format("2006-01-02 15:04:05.000")
	fmt.Printf("%s\n", ts)
	fmt.Printf("> %s %s\n", req.Method, req.URL.String())

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host != "" {
		fmt.Printf("> Host: %s\n", host)
	}

	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range req.Header[k] {
			fmt.Printf("> %s: %s\n", k, v)
		}
	}
	if req.ContentLength > 0 && req.Header.Get("Content-Length") == "" {
		fmt.Printf("> Content-Length: %d\n", req.ContentLength)
	}
}

func printResponseHeaders(resp *http.Response) {
	fmt.Printf("< %s %s\n", resp.Proto, resp.Status)
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range resp.Header[k] {
			fmt.Printf("< %s: %s\n", k, v)
		}
	}
	fmt.Println()
}

func (nc *NetClient) Do(method, targetURL string, body []byte, extraHeaders map[string]string) (*http.Response, []byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, targetURL, bodyReader)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}

	ua := nc.profile.UserAgent
	if ua == "" {
		ua = userAgents[0]
	}
	acceptLang := nc.profile.AcceptLanguage
	if acceptLang == "" {
		acceptLang = langProfiles[0].header
	}

	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", defaultAcceptHTML)
	req.Header.Set("Accept-Language", acceptLang)
	req.Header.Set("Accept-Encoding", "gzip")

	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	if cookieHeader := nc.cookies.HeaderValue(); cookieHeader != "" {
		req.Header.Set("Cookie", cookieHeader)
	}

	resp, err := nc.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	nc.cookies.UpdateFromResponse(resp)

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, fmt.Errorf("read response body: %w", err)
	}

	decodedBody, err := decodeBodyIfGzip(resp, rawBody)
	if err != nil {
		return resp, nil, err
	}

	return resp, decodedBody, nil
}

func decodeBodyIfGzip(resp *http.Response, raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	if !strings.EqualFold(strings.TrimSpace(resp.Header.Get("Content-Encoding")), "gzip") {
		return raw, nil
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("init gzip reader: %w", err)
	}
	defer gz.Close()

	out, err := io.ReadAll(gz)
	if err != nil {
		return nil, fmt.Errorf("decompress gzip body: %w", err)
	}
	return out, nil
}

// GetFollowingRedirects performs GET and follows 3xx redirects up to maxHops.
func (nc *NetClient) GetFollowingRedirects(startURL string, maxHops int) (*http.Response, []byte, *url.URL, error) {
	currentURL, err := url.Parse(startURL)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse URL %q: %w", startURL, err)
	}

	var referer string
	for hop := 0; hop <= maxHops; hop++ {
		headers := map[string]string{
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Upgrade-Insecure-Requests": "1",
		}
		if referer != "" {
			headers["Referer"] = referer
			headers["Sec-Fetch-Site"] = "same-origin"
		}

		resp, body, err := nc.Do(http.MethodGet, currentURL.String(), nil, headers)
		if err != nil {
			return nil, nil, currentURL, err
		}

		if isRedirectStatus(resp.StatusCode) {
			loc := resp.Header.Get("Location")
			if loc == "" {
				return resp, body, currentURL, nil
			}
			nextRel, err := url.Parse(loc)
			if err != nil {
				return resp, body, currentURL, fmt.Errorf("invalid redirect Location %q: %w", loc, err)
			}
			referer = currentURL.String()
			currentURL = currentURL.ResolveReference(nextRel)
			continue
		}

		return resp, body, currentURL, nil
	}

	return nil, nil, currentURL, fmt.Errorf("exceeded maximum redirect hops (%d)", maxHops)
}

func isRedirectStatus(code int) bool {
	switch code {
	case http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func FormatResponseHeaders(resp *http.Response) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\r\n", resp.Proto, resp.Status)
	_ = resp.Header.Write(&b)
	b.WriteString("\r\n")
	return b.String()
}
