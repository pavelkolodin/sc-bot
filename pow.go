package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	maxPoWIterations uint64 = 50_000_000
)

var (
	reTicket     = regexp.MustCompile(`(?:const|let|var)\s+TICKET\s*=\s*["']([^"']+)["']`)
	reSeed       = regexp.MustCompile(`(?:const|let|var)\s+SEED\s*=\s*["']([^"']+)["']`)
	reDifficulty = regexp.MustCompile(`(?:const|let|var)\s+DIFFICULTY\s*=\s*(\d+)`)
	reVerifyURL  = regexp.MustCompile(`(?:const|let|var)\s+VERIFY_URL\s*=\s*["']([^"']+)["']`)
)

type TicketPayload struct {
	ReturnURL     string `json:"return_url"`
	ServerScore   int    `json:"server_score"`
	Nonce         string `json:"nonce"`
	Exp           int64  `json:"exp"`
	ChallengeSeed string `json:"challenge_seed"`
	Difficulty    int    `json:"difficulty"`
}

type ChallengeParams struct {
	Ticket      string
	Seed        string
	Difficulty  int
	VerifyURL   string
	ServerScore int
	ReturnURL   string
}

type PoWResult struct {
	Seed        string
	Difficulty  int
	ServerScore int
	Nonce       uint64
	Attempts    uint64
	Hash        string
	ElapsedMs   int64
	Duration    time.Duration
}

type verifyRequest struct {
	Ticket     string `json:"ticket"`
	PowNonce   uint64 `json:"pow_nonce"`
	PowHash    string `json:"pow_hash"`
	ElapsedMs  int64  `json:"elapsed_ms"`
	Webdriver  bool   `json:"webdriver"`
	Canvas     string `json:"canvas"`
	Screen     string `json:"screen"`
	Lang       string `json:"lang"`
	TzOffset   int    `json:"tz_offset"`
	HasPlugins int    `json:"has_plugins"`
}

type verifyResponse struct {
	Action string `json:"action"`
	URL    string `json:"url"`
}

func DecodeTicketPayload(ticket string) (*TicketPayload, error) {
	parts := strings.SplitN(ticket, ".", 2)
	if len(parts) == 0 || parts[0] == "" {
		return nil, fmt.Errorf("empty ticket payload")
	}
	rawB64 := strings.TrimRight(parts[0], "=")
	decoded, err := base64.RawURLEncoding.DecodeString(rawB64)
	if err != nil {
		return nil, fmt.Errorf("decode ticket base64url: %w", err)
	}
	var payload TicketPayload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal ticket json: %w", err)
	}
	return &payload, nil
}

// ParseChallengeHTML detects and extracts botcheck Proof-of-Work parameters from HTML.
func ParseChallengeHTML(html []byte) (*ChallengeParams, bool, error) {
	text := string(html)

	mTicket := reTicket.FindStringSubmatch(text)
	mSeed := reSeed.FindStringSubmatch(text)
	mDiff := reDifficulty.FindStringSubmatch(text)
	mVerify := reVerifyURL.FindStringSubmatch(text)

	if len(mTicket) < 2 && len(mSeed) < 2 {
		return nil, false, nil
	}

	params := &ChallengeParams{
		VerifyURL: "verify.php",
	}
	if len(mTicket) >= 2 {
		params.Ticket = mTicket[1]
	}
	if len(mSeed) >= 2 {
		params.Seed = mSeed[1]
	}
	if len(mDiff) >= 2 {
		d, err := strconv.Atoi(mDiff[1])
		if err != nil {
			return nil, true, fmt.Errorf("parse difficulty %q: %w", mDiff[1], err)
		}
		params.Difficulty = d
	}
	if len(mVerify) >= 2 && mVerify[1] != "" {
		params.VerifyURL = mVerify[1]
	}

	if params.Ticket != "" {
		if tp, err := DecodeTicketPayload(params.Ticket); err == nil {
			params.ServerScore = tp.ServerScore
			params.ReturnURL = tp.ReturnURL
			if params.Seed == "" {
				params.Seed = tp.ChallengeSeed
			}
			if params.Difficulty == 0 {
				params.Difficulty = tp.Difficulty
			}
		}
	}

	if params.Ticket == "" || params.Seed == "" || params.Difficulty <= 0 {
		return nil, true, fmt.Errorf("incomplete challenge parameters (ticket=%t, seed=%q, difficulty=%d)",
			params.Ticket != "", params.Seed, params.Difficulty)
	}

	return params, true, nil
}

// SolveProofOfWork finds nonce >= 0 such that lowercase hex(SHA-256(seed + ":" + nonce))
// starts with `difficulty` zero hex characters.
func SolveProofOfWork(seed string, difficulty int) (*PoWResult, error) {
	if difficulty < 1 || difficulty > 64 {
		return nil, fmt.Errorf("invalid difficulty %d: must be between 1 and 64", difficulty)
	}

	fullZeroBytes := difficulty / 2
	oddNibble := difficulty%2 == 1

	prefix := seed + ":"
	buf := make([]byte, len(prefix), len(prefix)+24)
	copy(buf, prefix)

	start := time.Now()
	for nonce := uint64(0); nonce <= maxPoWIterations; nonce++ {
		candidate := strconv.AppendUint(buf[:len(prefix)], nonce, 10)
		sum := sha256.Sum256(candidate)

		matched := true
		for i := 0; i < fullZeroBytes; i++ {
			if sum[i] != 0 {
				matched = false
				break
			}
		}
		if matched && oddNibble && (sum[fullZeroBytes]&0xF0) != 0 {
			matched = false
		}

		if matched {
			dur := time.Since(start)
			return &PoWResult{
				Seed:       seed,
				Difficulty: difficulty,
				Nonce:      nonce,
				Attempts:   nonce + 1,
				Hash:       hex.EncodeToString(sum[:]),
				ElapsedMs:  dur.Milliseconds(),
				Duration:   dur,
			}, nil
		}
	}

	return nil, fmt.Errorf("proof-of-work exceeded %d iterations without solution", maxPoWIterations)
}

func SubmitVerification(nc *NetClient, challengeURL *url.URL, params *ChallengeParams, res *PoWResult) (*url.URL, string, error) {
	verifyRel, err := url.Parse(params.VerifyURL)
	if err != nil {
		return nil, "", fmt.Errorf("parse verify URL %q: %w", params.VerifyURL, err)
	}
	verifyURL := challengeURL.ResolveReference(verifyRel)

	profile := nc.profile
	if profile.Canvas == "" {
		profile = NewRandomBrowserProfile()
	}

	reqBody := verifyRequest{
		Ticket:     params.Ticket,
		PowNonce:   res.Nonce,
		PowHash:    res.Hash,
		ElapsedMs:  res.ElapsedMs,
		Webdriver:  false,
		Canvas:     profile.Canvas,
		Screen:     profile.Screen,
		Lang:       profile.Lang,
		TzOffset:   profile.TzOffset,
		HasPlugins: profile.HasPlugins,
	}

	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "", fmt.Errorf("marshal verification JSON: %w", err)
	}

	headers := map[string]string{
		"Content-Type":   "application/json",
		"Accept":         "*/*",
		"Origin":         challengeURL.Scheme + "://" + challengeURL.Host,
		"Referer":        challengeURL.String(),
		"Sec-Fetch-Dest": "empty",
		"Sec-Fetch-Mode": "cors",
		"Sec-Fetch-Site": "same-origin",
	}

	resp, body, err := nc.Do(http.MethodPost, verifyURL.String(), jsonBytes, headers)
	if err != nil {
		return nil, "", fmt.Errorf("post verification to %s: %w", verifyURL.String(), err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("verification endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var vResp verifyResponse
	if err := json.Unmarshal(body, &vResp); err != nil {
		return nil, "", fmt.Errorf("parse verification JSON response (%q): %w", strings.TrimSpace(string(body)), err)
	}

	if vResp.Action != "redirect" || vResp.URL == "" {
		return nil, vResp.Action, fmt.Errorf("verification did not issue redirect (action=%q, url=%q)", vResp.Action, vResp.URL)
	}

	targetRel, err := url.Parse(vResp.URL)
	if err != nil {
		return nil, vResp.Action, fmt.Errorf("parse redirect URL %q: %w", vResp.URL, err)
	}
	redirectURL := verifyURL.ResolveReference(targetRel)
	return redirectURL, vResp.Action, nil
}
