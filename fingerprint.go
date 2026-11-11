package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
)

// BrowserProfile holds a per-session randomized browser fingerprint and matching HTTP headers.
type BrowserProfile struct {
	UserAgent      string
	AcceptLanguage string
	Screen         string
	Lang           string
	TzOffset       int
	HasPlugins     int
	Canvas         string
}

var userAgents = []string{
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
}

var screenModes = []string{
	"1920x1080x24",
	"2560x1440x24",
	"1366x768x24",
	"1536x864x24",
	"1440x900x24",
	"1600x900x24",
	"1920x1200x24",
	"3840x2160x24",
}

type langProfile struct {
	lang   string
	header string
}

var langProfiles = []langProfile{
	{lang: "ru-RU", header: "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"},
	{lang: "en-US", header: "en-US,en;q=0.9"},
	{lang: "en-GB", header: "en-GB,en;q=0.9,en-US;q=0.8"},
	{lang: "de-DE", header: "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"},
	{lang: "fr-FR", header: "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"},
}

var tzOffsets = []int{-300, -240, -180, -120, -60, 0, 60, 240, 300}

// NewRandomBrowserProfile creates a cheap, randomized fingerprint without rendering any graphics.
func NewRandomBrowserProfile() BrowserProfile {
	lp := langProfiles[rand.IntN(len(langProfiles))]
	return BrowserProfile{
		UserAgent:      userAgents[rand.IntN(len(userAgents))],
		AcceptLanguage: lp.header,
		Screen:         screenModes[rand.IntN(len(screenModes))],
		Lang:           lp.lang,
		TzOffset:       tzOffsets[rand.IntN(len(tzOffsets))],
		HasPlugins:     1 + rand.IntN(6),
		Canvas:         randomCanvasDataURL(),
	}
}

// randomCanvasDataURL builds a PNG-prefixed data URL filled with cheap pseudo-random bytes
// instead of performing actual 2D canvas drawing.
func randomCanvasDataURL() string {
	pngSig := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
	randLen := 64 + rand.IntN(97) // 64..160 bytes
	buf := make([]byte, len(pngSig)+randLen)
	copy(buf, pngSig)

	for i := len(pngSig); i < len(buf); i += 8 {
		v := rand.Uint64()
		if i+8 <= len(buf) {
			binary.LittleEndian.PutUint64(buf[i:], v)
		} else {
			var tmp [8]byte
			binary.LittleEndian.PutUint64(tmp[:], v)
			copy(buf[i:], tmp[:len(buf)-i])
		}
	}
	return fmt.Sprintf("data:image/png;base64,%s", base64.StdEncoding.EncodeToString(buf))
}
