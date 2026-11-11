package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("app", flag.ContinueOnError)
	targetURL := fs.String("url", "", "Target URL to fetch (required)")
	outCookie := fs.String("outcookie", "", "Path to save resulting cookies (key=value per line)")
	inCookie := fs.String("cookie", "", "Path to load initial cookies (key=value per line)")
	outBody := fs.String("out", "", "Path to save final HTTP response body")
	outHeader := fs.String("outheader", "", "Path to save final HTTP response headers")
	stdoutHeaders := fs.Bool("stdoutheaders", false, "Print all HTTP request and response headers to stdout without bodies")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s --url <URL> [options]\n\nOptions:\n", os.Args[0])
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*targetURL) == "" {
		fs.Usage()
		return fmt.Errorf("--url is required")
	}

	parsedTarget, err := url.Parse(*targetURL)
	if err != nil || (parsedTarget.Scheme != "http" && parsedTarget.Scheme != "https") || parsedTarget.Host == "" {
		return fmt.Errorf("invalid --url %q: expected http:// or https:// URL with host", *targetURL)
	}

	cookies := NewCookieStore()
	if *inCookie != "" {
		if err := cookies.LoadFromFile(*inCookie); err != nil {
			return err
		}
	}

	profile := NewRandomBrowserProfile()
	nc := NewNetClient(cookies, profile, *stdoutHeaders)
	defer nc.Close()

	resp, body, currentURL, err := nc.GetFollowingRedirects(parsedTarget.String(), 10)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", parsedTarget.String(), err)
	}

	if strings.Contains(currentURL.Path, "botcheck/captcha.php") {
		return fmt.Errorf("server redirected to captcha page (%s); automated PoW cannot solve captcha", currentURL.String())
	}

	var powResult *PoWResult
	var verifyAction string
	var verifyRedirectURL string

	params, isChallenge, err := ParseChallengeHTML(body)
	if err != nil {
		return fmt.Errorf("parse challenge page (%s): %w", currentURL.String(), err)
	}

	if isChallenge {
		powResult, err = SolveProofOfWork(params.Seed, params.Difficulty)
		if err != nil {
			return fmt.Errorf("solve proof-of-work: %w", err)
		}
		powResult.ServerScore = params.ServerScore

		redirectURL, action, err := SubmitVerification(nc, currentURL, params, powResult)
		if err != nil {
			return err
		}
		verifyAction = action
		verifyRedirectURL = redirectURL.String()

		resp, body, currentURL, err = nc.GetFollowingRedirects(redirectURL.String(), 10)
		if err != nil {
			return fmt.Errorf("fetch post-verification target %s: %w", redirectURL.String(), err)
		}

		if strings.Contains(currentURL.Path, "botcheck/captcha.php") {
			return fmt.Errorf("post-verification redirect led to captcha (%s)", currentURL.String())
		}
		if _, stillChallenge, _ := ParseChallengeHTML(body); stillChallenge {
			return fmt.Errorf("server issued another PoW challenge after verification (%s)", currentURL.String())
		}
	}

	if *outCookie != "" {
		if err := cookies.SaveToFile(*outCookie); err != nil {
			return err
		}
	}
	if *outBody != "" {
		if err := os.WriteFile(*outBody, body, 0644); err != nil {
			return fmt.Errorf("write body file %q: %w", *outBody, err)
		}
	}
	if *outHeader != "" {
		headerText := FormatResponseHeaders(resp)
		if err := os.WriteFile(*outHeader, []byte(headerText), 0644); err != nil {
			return fmt.Errorf("write header file %q: %w", *outHeader, err)
		}
	}

	proto, remoteAddr := nc.LastTransportInfo()
	ipFamily := detectIPFamily(remoteAddr)

	if powResult != nil {
		hashRate := 0.0
		if secs := powResult.Duration.Seconds(); secs > 0 {
			hashRate = float64(powResult.Attempts) / secs
		}
		fmt.Printf("Proof-of-Work solved:\n")
		fmt.Printf("  seed:         %s\n", powResult.Seed)
		fmt.Printf("  difficulty:   %d (%d leading zero bits)\n", powResult.Difficulty, powResult.Difficulty*4)
		fmt.Printf("  server_score: %d\n", powResult.ServerScore)
		fmt.Printf("  nonce:        %d\n", powResult.Nonce)
		fmt.Printf("  attempts:     %d\n", powResult.Attempts)
		fmt.Printf("  hash:         %s\n", powResult.Hash)
		fmt.Printf("  elapsed_ms:   %d\n", powResult.ElapsedMs)
		fmt.Printf("  hash_rate:    %.0f H/s\n", hashRate)
		fmt.Printf("  fingerprint:  random (canvas_len=%d, screen=%s, lang=%s, tz_offset=%d, plugins=%d)\n",
			len(profile.Canvas), profile.Screen, profile.Lang, profile.TzOffset, profile.HasPlugins)
		fmt.Printf("  verify:       %s -> %s\n", verifyAction, verifyRedirectURL)
		fmt.Printf("  final_status: %s %s\n", resp.Proto, resp.Status)
		fmt.Printf("  transport:    %s via %s (%s)\n", proto, ipFamily, remoteAddr)
	} else {
		fmt.Printf("Proof-of-Work skipped: existing cookies accepted by server (no challenge issued).\n")
		fmt.Printf("  final_status: %s %s\n", resp.Proto, resp.Status)
		fmt.Printf("  transport:    %s via %s (%s)\n", proto, ipFamily, remoteAddr)
	}

	return nil
}

func detectIPFamily(remoteAddr string) string {
	if remoteAddr == "" {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "unknown"
	}
	if ip.To4() == nil {
		return "IPv6"
	}
	return "IPv4"
}
