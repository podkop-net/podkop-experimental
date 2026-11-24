//go:build podkop_slim && with_quic && with_utls && with_clash_api

package plan_test

// The outbounds podkop does not write itself, which the build of the package leaves out (the fork's
// include/podkop_full.go, registerFullOutbounds): an outbound JSON or a link may still name one.
func init() {
	slimLeftOut = []string{"anytls", "naive", "shadowtls", "snell", "ssh", "tor", "vmess"}
}
