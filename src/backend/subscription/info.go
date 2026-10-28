package subscription

import (
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
)

// The most of a text of a provider the page shows: a title is a name, a notice a few lines.
const (
	maxTitle    = 100
	maxAnnounce = 500
	maxPage     = 300
)

// ReadInfo reads what a provider tells of a subscription (the headers kept with its list,
// Answer.Info): its title, the traffic, when it ends, how often to download it, its pages
// and its notice. What cannot be read is left out; none when nothing can.
func ReadInfo(info map[string]string) *api.ProviderInfo {
	var read api.ProviderInfo
	if value := info["subscription-userinfo"]; value != "" {
		readUserInfo(value, &read)
	}
	read.Title = providerText(info["profile-title"], maxTitle, false)
	read.Announce = providerText(info["announce"], maxAnnounce, true)
	read.SupportURL = providerPage(info["support-url"])
	read.WebPageURL = providerPage(info["profile-web-page-url"])
	if hours, err := strconv.Atoi(strings.TrimSpace(info["profile-update-interval"])); err == nil && hours > 0 && hours <= 24*30 {
		read.UpdateHours = hours
	}
	read.Refill = unixTime(info["subscription-refill-date"])
	if read == (api.ProviderInfo{}) {
		return nil
	}
	return &read
}

// readUserInfo reads "upload=0; download=123; total=456; expire=1767225600": bytes used and
// the limit (0 is none), the end as Unix time (0 is none). Panels write the numbers as
// integers; some as decimals, some the time in milliseconds.
func readUserInfo(value string, read *api.ProviderInfo) {
	for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == ';' || r == ',' }) {
		key, number, found := strings.Cut(strings.TrimSpace(field), "=")
		if !found {
			continue
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(number), 64)
		if err != nil || parsed < 0 || math.IsInf(parsed, 0) || math.IsNaN(parsed) || parsed > math.MaxInt64/2 {
			continue
		}
		amount := int64(parsed)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "upload":
			read.Upload, read.Traffic = amount, true
		case "download":
			read.Download, read.Traffic = amount, true
		case "total":
			read.Total, read.Traffic = amount, true
		case "expire":
			read.Expire = unixTime(strconv.FormatInt(amount, 10))
		}
	}
}

// unixTime reads a time a provider writes as Unix seconds (some in milliseconds); 0 is none.
func unixTime(value string) *time.Time {
	number, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || number <= 0 || math.IsInf(number, 0) || number > math.MaxInt64/2 {
		return nil
	}
	seconds := int64(number)
	if seconds > 100_000_000_000 {
		seconds /= 1000
	}
	read := time.Unix(seconds, 0).UTC()
	return &read
}

// providerText is a text of a provider as the page may show it: "base64:" is decoded, what
// is no text or control is dropped (a notice keeps its line breaks), and the length is cut.
func providerText(value string, most int, lines bool) string {
	value = strings.TrimSpace(value)
	if rest, found := cutPrefixFold(value, "base64:"); found {
		decoded, ok := decodeBase64(strings.TrimSpace(rest))
		if !ok {
			return ""
		}
		value = decoded
	}
	if !utf8.ValidString(value) {
		return ""
	}
	value = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' && lines:
			return r
		case r == '\t' || r == '\n' || r == '\r':
			return ' '
		case unicode.IsControl(r) || r == ' ' || r == ' ':
			return -1
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	if utf8.RuneCountInString(value) > most {
		value = string([]rune(value)[:most]) + "…"
	}
	return value
}

// providerPage is a page of a provider the page may link to: HTTP or HTTPS only.
func providerPage(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxPage {
		return ""
	}
	page, err := url.Parse(value)
	if err != nil || (page.Scheme != "https" && page.Scheme != "http") || page.Host == "" {
		return ""
	}
	return page.String()
}

// bodyInfo reads what some providers write at the top of the list instead of the headers:
// lines "#profile-title: …", "#subscription-userinfo: …".
func bodyInfo(body []byte) map[string]string {
	text := strings.TrimSpace(strings.TrimPrefix(string(body), "\ufeff"))
	if !strings.Contains(text, "://") {
		decoded, isBase64 := decodeBase64(text)
		if !isBase64 {
			return nil
		}
		text = strings.TrimSpace(strings.TrimPrefix(decoded, "\ufeff"))
	}
	info := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			break
		}
		key, value, found := strings.Cut(strings.TrimSpace(strings.TrimPrefix(line, "#")), ":")
		key = strings.ToLower(strings.TrimSpace(key))
		if found && isInfoHeader(key) && strings.TrimSpace(value) != "" {
			info[key] = strings.TrimSpace(value)
		}
	}
	return info
}

func isInfoHeader(name string) bool {
	for _, known := range infoHeaders {
		if known == name {
			return true
		}
	}
	return false
}

func cutPrefixFold(value string, prefix string) (string, bool) {
	if len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix) {
		return value[len(prefix):], true
	}
	return value, false
}
