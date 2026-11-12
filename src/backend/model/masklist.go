package model

import (
	"bufio"
	"bytes"
	"slices"
	"strings"

	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"golang.org/x/net/publicsuffix"
)

// DefaultMaskLists are the public lists of names "Find a mask" tries beside its built-in ones,
// one name per line: the white SNI of Runnin4ik/dpi-detector (187 names; 133 of 188 lifted the
// limit on the operator the hand-over measured them on) and the whitelist cheburcheck.ru builds
// with its own 16 KB probe (2138 names). Each is a union over operators and times, so a name is a
// candidate only; the probe on the router's own path decides.
var DefaultMaskLists = []string{
	"https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/whitelist_sni.txt",
	"https://cheburcheck.ru/whitelist/domains.csv",
}

// maskLists are the lists a mask search downloads: those of "mask_list_url", or the default ones
// when it names none; none when "mask_list" turns them off.
func maskLists(settings *uci.Section) []string {
	if !settings.Bool("mask_list", true) {
		return nil
	}
	var lists []string
	for _, value := range settings.List("mask_list_url") {
		if value = strings.TrimSpace(value); value != "" && !slices.Contains(lists, value) {
			lists = append(lists, value)
		}
	}
	if len(lists) == 0 {
		return slices.Clone(DefaultMaskLists)
	}
	return lists
}

// MaskSite is the site of a name, its registrable domain by the public suffix list: the hosts of
// one site pass or fail together on a path. A name the list cannot place is its own site.
func MaskSite(name string) string {
	site, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return name
	}
	return site
}

// MaskNames are the candidates of a downloaded list of names, in its order: one name per site
// (the registrable domain, by the public suffix list), the shortest the list has of it, and none of
// a site skip already has. A whitelist lists many hosts of one site (hundreds of mail.ru), and they
// pass or fail together on a path, so one probe per site covers the list. Lines that are no host
// name a mask may carry (ValidMaskName), comments and blanks are left out.
func MaskNames(list []byte, skip []string) []string {
	taken := make(map[string]bool, len(skip))
	for _, name := range skip {
		taken[MaskSite(name)] = true
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
		site := MaskSite(name)
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
