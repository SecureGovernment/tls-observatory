package dnsWorker

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/SecureGovernment/tls-observatory/worker"
)

var (
	workerName = "dnsWorker"
	workerDesc = "Checks domains for a SPF, DMARC, and DNSSEC records."
)

//Use the google DNS servers as fallback
var DNSServer = "8.8.8.8:53"

func init() {
	runner := new(eval)
	worker.RegisterPrinter(workerName, worker.Info{Runner: runner, Description: workerDesc})
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(cfg.Servers) > 0 {
		//if there are configured nameservers use them
		DNSServer = strings.Join([]string{cfg.Servers[0], cfg.Port}, ":")
	}
	worker.RegisterBeforeWorker(workerName, worker.Info{Runner: runner, Description: workerDesc})
}

// Result describes the result produced by DNSWorker
type Result struct {
	Host        string   	 `json:"host"`
	HasSPF      bool     	 `json:"has_spf"`
	HasOldSPF	bool		 `json:"has_old_spf"`
	OldSPF		[]string	 `json:"old_spf"`
	SPF     	[]string 	 `json:"spf"`
	HasDMARC	bool	 	 `json:"has_dmarc"`
	DMARC		[]string	 `json:"dmarc"`
	HasDNSSEC	bool		 `json:"has_dnssec"`
	DNSSEC		[]string	 `json:"dnssec"`
}

type eval struct{}

// Run implements the worker interface.It is called to get the worker results.
func (e eval) Run(in worker.Input, resChan chan worker.Result) {
	result := worker.Result{WorkerName: workerName, Success: true}
	dnsRes := Result{}

	host := in.Target + "."

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeSPF)

	client := dns.Client{}
	client.Net = "tcp"
	client.SingleInflight = true
	res, _, err := client.Exchange(msg, DNSServer)

	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("SPF lookup failed for %s: %v", host, err))
	}

	if res.Rcode != dns.RcodeSuccess {
		result.Errors = append(result.Errors, fmt.Sprintf("SPF lookup failed for %s with %s", host, dns.RcodeToString[res.Rcode]))
	}

	for _, rr := range res.Answer {
		if record, ok := rr.(*dns.SPF); ok {
			dnsRes.HasOldSPF = true
			dnsRes.SPF = append(dnsRes.OldSPF, record.String())
		}
	}

	msg.SetQuestion(dns.Fqdn(host), dns.TypeTXT)
	res, _, err = client.Exchange(msg, DNSServer)

	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("TXT SPF lookup failed for %s: %v", host, err))
	}

	if res.Rcode != dns.RcodeSuccess {
		result.Errors = append(result.Errors, fmt.Sprintf("TXT SPF lookup failed for %s with %s", host, dns.RcodeToString[res.Rcode]))
	}

	for _, rr := range res.Answer {
		if record, ok := rr.(*dns.TXT); ok {
			for _, textRecord := range record.Txt {
				if(strings.Contains(strings.ToLower(textRecord), "spf")){
					dnsRes.HasSPF = true
					dnsRes.SPF = append(dnsRes.SPF, record.String())
				}
			}
		}
	}

	msg.SetQuestion("_dmarc." + dns.Fqdn(host), dns.TypeTXT)
	res, _, err = client.Exchange(msg, DNSServer)

	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("DMARC lookup failed for %s: %v", host, err))
	}

	if res.Rcode != dns.RcodeSuccess {
		result.Errors = append(result.Errors, fmt.Sprintf("DMARC lookup failed for %s with %s", host, dns.RcodeToString[res.Rcode]))
	}

	for _, rr := range res.Answer {
		if record, ok := rr.(*dns.TXT); ok {
			for _, textRecord := range record.Txt {
				if(strings.Contains(strings.ToLower(textRecord), "dmarc")){
					dnsRes.HasDMARC = true
					dnsRes.DMARC = append(dnsRes.DMARC, record.String())
				}
			}
		}
	}

	msg.SetQuestion(dns.Fqdn(host), dns.TypeDNSKEY)
	res, _, err = client.Exchange(msg, DNSServer)

	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("DNSSEC lookup failed for %s: %v", host, err))
	}

	if res.Rcode != dns.RcodeSuccess {
		result.Errors = append(result.Errors, fmt.Sprintf("DNSSEC lookup failed for %s with %s", host, dns.RcodeToString[res.Rcode]))
	}

	for _, rr := range res.Answer {
		if record, ok := rr.(*dns.DNSKEY); ok {
			dnsRes.HasDNSSEC = true
			dnsRes.DNSSEC = append(dnsRes.DNSSEC, record.String())
		}
	}

	if dnsRes.HasSPF || dnsRes.HasDMARC || dnsRes.HasDNSSEC {
		dnsRes.Host = host
	}

	response, err := json.Marshal(dnsRes)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		result.Success = false
	} else {
		result.Success = true
		result.Result = response
	}

	resChan <- result
}

func (e eval) AnalysisPrinter(input []byte, printAll interface{}) (results []string, err error) {
	var r Result
	err = json.Unmarshal(input, &r)
	if err != nil {
		err = fmt.Errorf("DNS worker: failed to parse results: %v", err)
		return
	}

	if !r.HasSPF && !r.HasOldSPF {
		results = append(results, "* SPF records: not found")
	} else {
		if(r.HasOldSPF){
			results = append(results, "* Old SPF records: found")
			for _, spfRecord := range r.OldSPF {
				results = append(results, fmt.Sprintf("  - Old SPF record '%s' for '%s'", spfRecord, r.Host))
			}
		}
		if(r.HasSPF){
			results = append(results, "* SPF records: found")
			for _, spfRecord := range r.SPF {
				results = append(results, fmt.Sprintf("  - SPF record '%s' for '%s'", spfRecord, r.Host))
			}
		}
	}

	if !r.HasDMARC {
		results = append(results, "* DMARC records: not found")
	} else {
		results = append(results, "* DMARC records: found")
		for _, spfRecord := range r.DMARC {
			results = append(results, fmt.Sprintf("  - DMARC record '%s' for '%s'", spfRecord, r.Host))
		}
	}

	if !r.HasDNSSEC {
		results = append(results, "* DNSSEC records: not found")
	} else {
		results = append(results, "* DNSSEC records: found")
		for _, dnssecRecord := range r.DNSSEC {
			results = append(results, fmt.Sprintf("  - DNSSEC record '%s' for '%s'", dnssecRecord, r.Host))
		}
	}

	return results, nil
}
