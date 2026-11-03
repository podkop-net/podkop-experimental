package ctl

import "github.com/podkop-net/podkop-experimental/src/backend/diag"

// compat: page-answers
// The answers of the checks in the shapes the shell backend printed: the names and the
// order of the fields, and a flag as a number, 0 or 1. The user interface of podkop 0.7
// reads them; a typed API would print diag's values as they are.

type firewallAnswer struct {
	TableExist                int `json:"table_exist"`
	RulesMangleExist          int `json:"rules_mangle_exist"`
	RulesMangleCounters       int `json:"rules_mangle_counters"`
	RulesMangleOutputExist    int `json:"rules_mangle_output_exist"`
	RulesMangleOutputCounters int `json:"rules_mangle_output_counters"`
	RulesProxyExist           int `json:"rules_proxy_exist"`
	RulesProxyCounters        int `json:"rules_proxy_counters"`
	RulesOtherMarkExist       int `json:"rules_other_mark_exist"`
}

func answerFirewall(found *diag.Firewall) firewallAnswer {
	return firewallAnswer{
		TableExist:       asNumber(found.Table),
		RulesMangleExist: asNumber(found.Mangle), RulesMangleCounters: asNumber(found.MangleCounted),
		RulesMangleOutputExist: asNumber(found.MangleOutput), RulesMangleOutputCounters: asNumber(found.MangleOutputCounted),
		RulesProxyExist: asNumber(found.Proxy), RulesProxyCounters: asNumber(found.ProxyCounted),
		RulesOtherMarkExist: asNumber(len(found.ForeignMarks) > 0),
	}
}

// singBoxAnswer has what the shell backend checked of a sing-box package and service of
// its own: here they are a part of the backend, and so always there.
type singBoxAnswer struct {
	Installed        int `json:"sing_box_installed"`
	VersionOK        int `json:"sing_box_version_ok"`
	ServiceExist     int `json:"sing_box_service_exist"`
	AutostartDisable int `json:"sing_box_autostart_disabled"`
	ProcessRunning   int `json:"sing_box_process_running"`
	PortsListening   int `json:"sing_box_ports_listening"`
}

func answerSingBox(found *diag.SingBox) singBoxAnswer {
	return singBoxAnswer{Installed: 1, VersionOK: 1, ServiceExist: 1, AutostartDisable: 1, ProcessRunning: asNumber(found.Running), PortsListening: asNumber(found.Listening)}
}

// DNSAnswer is the answer of check_dns_available. dns_type and dns_server are those of the first
// server of the list, dns_status whether any server of it answers; dns_servers are all of them.
type DNSAnswer struct {
	DNSType            string            `json:"dns_type"`
	DNSServer          string            `json:"dns_server"`
	DNSStatus          int               `json:"dns_status"`
	DNSMode            string            `json:"dns_mode"`
	DNSServers         []dnsServerAnswer `json:"dns_servers"`
	DNSOnRouter        int               `json:"dns_on_router"`
	BootstrapDNSServer string            `json:"bootstrap_dns_server"`
	BootstrapDNSStatus int               `json:"bootstrap_dns_status"`
	DHCPConfigStatus   int               `json:"dhcp_config_status"`
}

// dnsServerAnswer is a server of the list; providers are the servers of the provider's row,
// refusal the rcode of a server that replied without an answer (status 0 then).
type dnsServerAnswer struct {
	Type      string   `json:"type"`
	Server    string   `json:"server"`
	Providers []string `json:"providers,omitempty"`
	Status    int      `json:"status"`
	Refusal   string   `json:"refusal,omitempty"`
}

// AnswerDNS is the answer of check_dns_available to what the check found.
func AnswerDNS(found *diag.DNS) DNSAnswer {
	servers := []dnsServerAnswer{}
	for _, upstream := range found.Upstreams {
		servers = append(servers, dnsServerAnswer{Type: upstream.Type, Server: upstream.Server, Providers: upstream.Providers, Status: asNumber(upstream.Answers), Refusal: upstream.Refusal})
	}
	return DNSAnswer{
		DNSType: found.Type, DNSServer: found.Server, DNSStatus: asNumber(found.ServerAnswers), DNSMode: found.Mode, DNSServers: servers,
		DNSOnRouter: asNumber(found.RouterAnswers), BootstrapDNSServer: found.Bootstrap, BootstrapDNSStatus: asNumber(found.BootstrapAnswers),
		DHCPConfigStatus: asNumber(found.DHCPAsksBackend),
	}
}

type systemAnswer struct {
	PodkopVersion       string `json:"podkop_version"`
	PodkopLatestVersion string `json:"podkop_latest_version"`
	LuCIAppVersion      string `json:"luci_app_version"`
	SingBoxVersion      string `json:"sing_box_version"`
	// Engine is what the sing-box inside is, for a person (podkop.Engine)
	Engine         string `json:"engine"`
	OpenWrtVersion string `json:"openwrt_version"`
	DeviceModel    string `json:"device_model"`
}

func answerSystem(found *diag.System, engine string) systemAnswer {
	return systemAnswer{PodkopVersion: found.PodkopVersion, PodkopLatestVersion: found.PodkopLatestVersion, LuCIAppVersion: found.LuCIAppVersion,
		SingBoxVersion: found.SingBoxVersion, Engine: engine, OpenWrtVersion: found.OpenWrtVersion, DeviceModel: found.DeviceModel}
}
