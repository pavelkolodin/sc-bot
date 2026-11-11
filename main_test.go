package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCookieStoreLoadSaveAndDelete(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.txt")
	content := "# comment\n\nPHPSESSID=abc123\nq_token=val==with=equals\n"
	if err := os.WriteFile(inPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cs := NewCookieStore()
	if err := cs.LoadFromFile(inPath); err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if cs.Count() != 2 {
		t.Fatalf("expected 2 cookies, got %d", cs.Count())
	}
	if got := cs.HeaderValue(); got != "PHPSESSID=abc123; q_token=val==with=equals" {
		t.Fatalf("unexpected HeaderValue: %q", got)
	}

	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{
				"q_last_guest_name=deleted; expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0; path=/forum/",
				"PHPSESSID=xyz789; path=/forum/",
				"q_botcheck_pass=pass.sig; Max-Age=43200; path=/forum/; secure; HttpOnly",
			},
		},
	}
	cs.UpdateFromResponse(resp)

	if cs.Count() != 3 {
		t.Fatalf("expected 3 cookies after update, got %d (%s)", cs.Count(), cs.HeaderValue())
	}

	// Verify Max-Age=0 deletion of an existing cookie
	respDel := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{
				"q_token=deleted; expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0",
			},
		},
	}
	cs.UpdateFromResponse(respDel)
	if cs.Count() != 2 {
		t.Fatalf("expected 2 cookies after delete, got %d", cs.Count())
	}

	outPath := filepath.Join(dir, "out.txt")
	if err := cs.SaveToFile(outPath); err != nil {
		t.Fatalf("SaveToFile: %v", err)
	}
	saved, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	expected := "PHPSESSID=xyz789\nq_botcheck_pass=pass.sig\n"
	if string(saved) != expected {
		t.Fatalf("saved cookies mismatch:\ngot:\n%s\nwant:\n%s", string(saved), expected)
	}
}

func TestSolveProofOfWorkOddAndEvenDifficulties(t *testing.T) {
	seed := "49296f6fca1f1fb0"
	for _, diff := range []int{1, 2, 3, 4} {
		res, err := SolveProofOfWork(seed, diff)
		if err != nil {
			t.Fatalf("difficulty %d failed: %v", diff, err)
		}
		prefix := strings.Repeat("0", diff)
		if !strings.HasPrefix(res.Hash, prefix) {
			t.Fatalf("difficulty %d: hash %q does not start with %q", diff, res.Hash, prefix)
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", seed, res.Nonce)))
		wantHex := hex.EncodeToString(sum[:])
		if res.Hash != wantHex {
			t.Fatalf("difficulty %d: hash mismatch got %q want %q", diff, res.Hash, wantHex)
		}
		if res.Attempts != res.Nonce+1 {
			t.Fatalf("attempts %d != nonce+1 (%d)", res.Attempts, res.Nonce+1)
		}
		// Ensure it found the smallest nonce >= 0
		for n := uint64(0); n < res.Nonce; n++ {
			s := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", seed, n)))
			if strings.HasPrefix(hex.EncodeToString(s[:]), prefix) {
				t.Fatalf("difficulty %d: skipped smaller valid nonce %d (found %d)", diff, n, res.Nonce)
			}
		}
	}
}

func TestParseChallengeHTML(t *testing.T) {
	payloadJSON := `{"return_url":"http://nosql.ru/forum/forum.php?fid=8","server_score":90,"nonce":"abcd1234","exp":1794383344,"challenge_seed":"deadbeef01020304","difficulty":4}`
	ticket := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON)) + ".fakesig"

	html := fmt.Sprintf(`<!DOCTYPE html><html><script>
const TICKET = "%s";
const SEED = "deadbeef01020304";
const DIFFICULTY = 4;
const VERIFY_URL = "verify.php";
</script></html>`, ticket)

	params, isChal, err := ParseChallengeHTML([]byte(html))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isChal {
		t.Fatalf("expected isChallenge=true")
	}
	if params.Seed != "deadbeef01020304" || params.Difficulty != 4 || params.ServerScore != 90 || params.VerifyURL != "verify.php" {
		t.Fatalf("unexpected parsed params: %+v", params)
	}

	// Non-challenge page
	_, isChal2, err2 := ParseChallengeHTML([]byte("<html><body><title>Forum</title></body></html>"))
	if err2 != nil || isChal2 {
		t.Fatalf("expected non-challenge page, got isChal=%v err=%v", isChal2, err2)
	}
}

func TestEndToEndLocalPoWFlowAndReuseCookie(t *testing.T) {
	seed := "a1b2c3d4e5f60708"
	diff := 3
	payloadJSON := fmt.Sprintf(`{"return_url":"/forum/forum.php?fid=8","server_score":100,"nonce":"11223344","exp":2000000000,"challenge_seed":"%s","difficulty":%d}`, seed, diff)
	ticket := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON)) + ".sig"
	expectedBody := "<html><body>FINAL_FORUM_PAGE_OK</body></html>"

	mux := http.NewServeMux()
	mux.HandleFunc("/forum/forum.php", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("q_botcheck_pass")
		if err != nil || c.Value != "passed-token-123" {
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "sess1", Path: "/forum/"})
			http.SetCookie(w, &http.Cookie{Name: "q_last_guest_name", Value: "deleted", MaxAge: -1, Path: "/forum/"})
			http.Redirect(w, r, "botcheck/challenge.php?ticket=init", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(expectedBody))
	})
	mux.HandleFunc("/forum/botcheck/challenge.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<script>
const TICKET = "%s";
const SEED = "%s";
const DIFFICULTY = %d;
const VERIFY_URL = "verify.php";
</script>`, ticket, seed, diff)
	})
	mux.HandleFunc("/forum/botcheck/verify.php", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req verifyRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if req.Ticket != ticket || req.Webdriver || !strings.HasPrefix(req.Canvas, "data:image/png;base64,") {
			_, _ = w.Write([]byte(`{"action":"captcha","url":"captcha.php"}`))
			return
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", seed, req.PowNonce)))
		h := hex.EncodeToString(sum[:])
		if !strings.HasPrefix(h, strings.Repeat("0", diff)) || h != req.PowHash {
			http.Error(w, "bad pow", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "q_botcheck_pass", Value: "passed-token-123", Path: "/forum/", MaxAge: 43200})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"redirect","url":"/forum/forum.php?fid=8"}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	cookieFile := filepath.Join(dir, "cookies.txt")
	outFile := filepath.Join(dir, "body.html")
	headerFile := filepath.Join(dir, "headers.txt")

	// Capture stdout from run() to inspect --stdoutheaders format and PoW output
	origStdout := os.Stdout
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = wPipe

	runErr := run([]string{
		"--url", srv.URL + "/forum/forum.php?fid=8",
		"--outcookie", cookieFile,
		"--out", outFile,
		"--outheader", headerFile,
		"--stdoutheaders",
	})

	_ = wPipe.Close()
	os.Stdout = origStdout

	var stdoutBuf bytes.Buffer
	_, _ = io.Copy(&stdoutBuf, rPipe)
	_ = rPipe.Close()

	if runErr != nil {
		t.Fatalf("first run failed: %v\nstdout:\n%s", runErr, stdoutBuf.String())
	}

	gotBody, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotBody) != expectedBody {
		t.Fatalf("body mismatch: got %q want %q", string(gotBody), expectedBody)
	}

	gotHeaders, err := os.ReadFile(headerFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gotHeaders), "200 OK") {
		t.Fatalf("expected 200 OK in outheader, got:\n%s", string(gotHeaders))
	}

	stdoutText := stdoutBuf.String()
	// Check timestamp format YYYY-MM-DD HH:MM:SS.mmm
	tsRe := regexp.MustCompile(`(?m)^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$`)
	if !tsRe.MatchString(stdoutText) {
		t.Fatalf("missing timestamp in stdoutheaders output:\n%s", stdoutText)
	}
	// Body must NOT appear in stdoutheaders
	if strings.Contains(stdoutText, "FINAL_FORUM_PAGE_OK") {
		t.Fatalf("body leaked into stdoutheaders output")
	}

	// Second run using saved cookies should skip PoW
	outFile2 := filepath.Join(dir, "body2.html")
	if err := run([]string{
		"--url", srv.URL + "/forum/forum.php?fid=8",
		"--cookie", cookieFile,
		"--out", outFile2,
	}); err != nil {
		t.Fatalf("second run with --cookie failed: %v", err)
	}
	gotBody2, err := os.ReadFile(outFile2)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotBody2) != expectedBody {
		t.Fatalf("second run body mismatch: got %q want %q", string(gotBody2), expectedBody)
	}
}

func TestHTTP2AndHTTP1Fallback(t *testing.T) {
	// Test HTTP/2 TLS server
	h2Srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "proto=%s", r.Proto)
	}))
	h2Srv.EnableHTTP2 = true
	h2Srv.StartTLS()
	defer h2Srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(h2Srv.Certificate())

	cs := NewCookieStore()
	nc := NewNetClient(cs, NewRandomBrowserProfile(), false)
	defer nc.Close()

	nc.primaryTransport.TLSClientConfig = h2Srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	nc.primaryTransport.TLSClientConfig.RootCAs = pool
	nc.http1Transport.TLSClientConfig = nc.http1Transport.TLSClientConfig.Clone()
	nc.http1Transport.TLSClientConfig.RootCAs = pool

	resp, body, _, err := nc.GetFollowingRedirects(h2Srv.URL, 2)
	if err != nil {
		t.Fatalf("HTTP/2 request failed: %v", err)
	}
	if resp.Proto != "HTTP/2.0" || string(body) != "proto=HTTP/2.0" {
		t.Fatalf("expected HTTP/2.0, got proto=%q body=%q", resp.Proto, string(body))
	}

	// Test HTTP/1.1-only TLS server
	h1Srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "proto=%s", r.Proto)
	}))
	h1Srv.EnableHTTP2 = false
	h1Srv.StartTLS()
	defer h1Srv.Close()

	pool1 := x509.NewCertPool()
	pool1.AddCert(h1Srv.Certificate())

	nc2 := NewNetClient(NewCookieStore(), NewRandomBrowserProfile(), false)
	defer nc2.Close()
	nc2.primaryTransport.TLSClientConfig = h1Srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	nc2.primaryTransport.TLSClientConfig.RootCAs = pool1
	nc2.http1Transport.TLSClientConfig = nc2.http1Transport.TLSClientConfig.Clone()
	nc2.http1Transport.TLSClientConfig.RootCAs = pool1

	resp1, body1, _, err := nc2.GetFollowingRedirects(h1Srv.URL, 2)
	if err != nil {
		t.Fatalf("HTTP/1.1 fallback failed: %v", err)
	}
	if resp1.Proto != "HTTP/1.1" || string(body1) != "proto=HTTP/1.1" {
		t.Fatalf("expected HTTP/1.1 fallback, got proto=%q body=%q", resp1.Proto, string(body1))
	}
}

func TestDialPreferIPv6FallbackLocalhost(t *testing.T) {
	// Start listener on 127.0.0.1 only (so IPv6 ::1 fails if resolved or succeeds when IPv4 fallback runs)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	conn, err := dialPreferIPv6(t.Context(), "tcp", net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatalf("dialPreferIPv6 failed on localhost IPv4 fallback: %v", err)
	}
	_ = conn.Close()
}

func TestRandomBrowserProfileAndCanvasFingerprint(t *testing.T) {
	seenCanvas := make(map[string]struct{})
	for i := 0; i < 8; i++ {
		p := NewRandomBrowserProfile()
		if !strings.HasPrefix(p.Canvas, "data:image/png;base64,") {
			t.Fatalf("unexpected canvas prefix: %q", p.Canvas)
		}
		rawB64 := strings.TrimPrefix(p.Canvas, "data:image/png;base64,")
		decoded, err := base64.StdEncoding.DecodeString(rawB64)
		if err != nil {
			t.Fatalf("canvas base64 decode failed: %v", err)
		}
		pngSig := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
		if !bytes.HasPrefix(decoded, pngSig) {
			t.Fatalf("decoded canvas missing PNG signature")
		}
		if len(decoded) < 72 {
			t.Fatalf("decoded canvas unexpectedly short: %d bytes", len(decoded))
		}
		if p.UserAgent == "" || p.Screen == "" || p.Lang == "" || p.HasPlugins <= 0 {
			t.Fatalf("incomplete profile: %+v", p)
		}
		seenCanvas[p.Canvas] = struct{}{}
	}
	if len(seenCanvas) < 6 {
		t.Fatalf("expected randomized canvas fingerprints across runs, got only %d unique out of 8", len(seenCanvas))
	}
}
