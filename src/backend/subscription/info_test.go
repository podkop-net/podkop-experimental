package subscription

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// What panels send: Marzban and Remnawave write integers and a title in "base64:"; others
// decimals, the end in milliseconds, a plain title.
func TestReadInfo(t *testing.T) {
	read := ReadInfo(map[string]string{
		"subscription-userinfo":   "upload=1024; download=2147483648; total=107374182400; expire=1767225600",
		"profile-title":           "base64:" + base64.StdEncoding.EncodeToString([]byte("Мой VPN")),
		"profile-update-interval": "12",
		"support-url":             "https://t.me/support_bot",
		"profile-web-page-url":    "https://panel.example/sub/X",
		"announce":                "base64:" + base64.RawURLEncoding.EncodeToString([]byte("Работы 1 ноября\nс 02:00")),
	})
	require.NotNil(t, read)
	require.Equal(t, "Мой VPN", read.Title)
	require.True(t, read.Traffic)
	require.Equal(t, int64(1024), read.Upload)
	require.Equal(t, int64(2147483648), read.Download)
	require.Equal(t, int64(107374182400), read.Total)
	require.Equal(t, time.Unix(1767225600, 0).UTC(), *read.Expire)
	require.Equal(t, 12, read.UpdateHours)
	require.Equal(t, "https://t.me/support_bot", read.SupportURL)
	require.Equal(t, "https://panel.example/sub/X", read.WebPageURL)
	require.Equal(t, "Работы 1 ноября\nс 02:00", read.Announce)

	read = ReadInfo(map[string]string{"subscription-userinfo": "upload=0.0,download=1.5E9 , total=0; expire=1767225600000", "profile-title": "Plain\ttitle\x07"})
	require.Equal(t, int64(1500000000), read.Download)
	require.Zero(t, read.Total, "0 is no limit")
	require.Equal(t, time.Unix(1767225600, 0).UTC(), *read.Expire, "milliseconds")
	require.Equal(t, "Plain title", read.Title, "no control characters")

	read = ReadInfo(map[string]string{"subscription-userinfo": "upload=0; download=0; total=0; expire=0"})
	require.True(t, read.Traffic, "told, all of it 0")
	require.Nil(t, read.Expire, "0 is no end")

	// what the page must not take: links of other schemes, broken base64, junk numbers
	read = ReadInfo(map[string]string{
		"support-url":             "javascript:alert(1)",
		"profile-web-page-url":    "ftp://panel.example/",
		"profile-title":           "base64:%%%",
		"profile-update-interval": "0",
		"subscription-userinfo":   "upload=-5; download=NaN; total=abc",
	})
	require.Nil(t, read, "nothing can be read")
	require.Nil(t, ReadInfo(nil))

	long := strings.Repeat("я", 300)
	require.Equal(t, maxTitle+1, len([]rune(ReadInfo(map[string]string{"profile-title": long}).Title)), "cut, with an ellipsis")
}

// Some providers put the headers as lines at the top of the list, in base64 or not; a header
// wins over such a line.
func TestBodyInfo(t *testing.T) {
	plain := "#profile-title: base64:" + base64.StdEncoding.EncodeToString([]byte("Body title")) + "\n" +
		"#subscription-userinfo: upload=1; download=2; total=3; expire=0\n" +
		"#something-else: 1\n" +
		"vless://u@a.example:443#NL\n#profile-update-interval: 5\n"
	info := bodyInfo([]byte(plain))
	require.Equal(t, map[string]string{
		"profile-title":         "base64:" + base64.StdEncoding.EncodeToString([]byte("Body title")),
		"subscription-userinfo": "upload=1; download=2; total=3; expire=0",
	}, info, "the lines before the first link only")
	require.Equal(t, info, bodyInfo([]byte(base64.StdEncoding.EncodeToString([]byte(plain)))))
	require.Nil(t, bodyInfo([]byte("not base64 at all !")))

	answer := &Answer{Body: []byte(plain), Header: http.Header{}}
	answer.Header.Set("Profile-Title", "Header title")
	read := ReadInfo(answer.Info())
	require.Equal(t, "Header title", read.Title)
	require.Equal(t, int64(3), read.Total)
}
