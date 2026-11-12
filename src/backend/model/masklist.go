package model

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"golang.org/x/net/publicsuffix"
)

// DefaultMaskListURL is the public list of names "Find a mask" tries after its built-in ones: the
// whitelist of hxehex/russia-mobile-internet-whitelist, one name per line. It is the whitelist of
// the mobile shutdowns, a union over operators, so a name is a candidate only; the probe on the
// router's own path decides.
const DefaultMaskListURL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt"

// maskListURL is the list a mask search downloads: "mask_list_url", or the default one; "" when
// "mask_list" turns it off.
func maskListURL(settings *uci.Section) string {
	if !settings.Bool("mask_list", true) {
		return ""
	}
	if value := strings.TrimSpace(settings.Get("mask_list_url")); value != "" {
		return value
	}
	return DefaultMaskListURL
}

// MaskNames are the candidates of a downloaded list of names, in its order: one name per site
// (the registrable domain, by the public suffix list), the shortest the list has of it, and none of
// a site skip already has. A whitelist lists many hosts of one site (hundreds of mail.ru), and they
// pass or fail together on a path, so one probe per site covers the list. Lines that are no host
// name a mask may carry (ValidMaskName), comments and blanks are left out.
func MaskNames(list []byte, skip []string) []string {
	siteOf := func(name string) string {
		site, err := publicsuffix.EffectiveTLDPlusOne(name)
		if err != nil {
			return name
		}
		return site
	}
	taken := make(map[string]bool, len(skip))
	for _, name := range skip {
		taken[siteOf(name)] = true
	}
	var sites []string
	shortest := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(list))
	for scanner.Scan() {
		line := scanner.Text()
		if index := strings.IndexByte(line, '#'); index >= 0 {
			line = line[:index]
		}
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(line)), ".")
		name = strings.TrimPrefix(name, "*.")
		if !ValidMaskName(name) {
			continue
		}
		site := siteOf(name)
		if taken[site] {
			continue
		}
		known, seen := shortest[site]
		switch {
		case !seen:
			sites = append(sites, site)
			shortest[site] = name
		case len(name) < len(known):
			shortest[site] = name
		}
	}
	names := make([]string, 0, len(sites))
	for _, site := range sites {
		names = append(names, shortest[site])
	}
	return names
}
