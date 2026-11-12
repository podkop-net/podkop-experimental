package engine

// WhiteSNICandidates are the names SuggestMask tries as a tls.spoof target when the caller gives
// none: a server's own cover is often not on an operator's 16-20KB-limit whitelist, and one of
// these on the wire lifts the limit. The list is the vetted set measured 2026-11-07 (every one
// lifted the limit on the tested broadband operator; a published RU list added ~71% more, so the
// set is a starting point, not exhaustive — the probe stops at the first that works). Picked for
// being plausible destinations and off the obvious blocklists; order is not load-bearing, the
// probe takes whichever answers full first.
var WhiteSNICandidates = []string{
	"asuracomic.net",
	"azure.com",
	"callofduty.com",
	"centurygame.com",
	"crowdsec.net",
	"deepl.com",
	"dji.com",
	"dribbble.com",
	"envato.com",
	"faceit.com",
	"finviz.com",
	"fontawesome.com",
	"gameforge.com",
	"gdms.cloud",
	"gdz.ru",
	"geeksforgeeks.org",
	"glideapps.com",
	"growthbook.io",
	"hamsterkombatgame.io",
	"iaea.org",
	"kas.pr",
	"kontur.ru",
	"lichess.org",
	"litnet.com",
	"mcafee.com",
	"mxtoolbox.com",
	"myfitnesspal.com",
	"nist.gov",
	"nodejs.org",
	"note.com",
	"online-python.com",
	"perplexity.ai",
	"sony.tv",
	"ssl-images-amazon.com",
	"steamproxy.net",
	"synology.com",
	"tesla.com",
	"timesofisrael.com",
	"tracker.gg",
	"trello.com",
	"twilio.com",
	"udemy.com",
	"vimeo.com",
	"w3.org",
	"windy.com",
	"xiaomi.com",
}

// NamesOf gives names one by one on a closed channel, for SuggestMask.
func NamesOf(names []string) <-chan string {
	out := make(chan string, len(names))
	for _, name := range names {
		out <- name
	}
	close(out)
	return out
}
