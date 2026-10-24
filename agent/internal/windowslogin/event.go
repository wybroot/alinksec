// Package windowslogin protects explicitly selected remote Windows logon types.
// Event identities and audit coverage never depend on localized message text.
package windowslogin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const provider = "Microsoft-Windows-Security-Auditing"
const providerGUID = "{54849625-5478-4994-a5ba-3e3b0328c30d}"
const maxXML = 64 << 10

type Record struct {
	ID          uint64
	Fingerprint string
	Time        time.Time
	Attempt     *Attempt
	RawXML      string
	EventID     string
}
type Attempt struct {
	IP        netip.Addr
	Account   string
	LogonType int
	Failed    bool
	Status    string
	SubStatus string
}

type eventXML struct {
	XMLName xml.Name
	System  []struct {
		Provider []struct {
			Name string `xml:"Name,attr"`
			GUID string `xml:"Guid,attr"`
		} `xml:"Provider"`
		IDs     []string `xml:"EventID"`
		Records []string `xml:"EventRecordID"`
		Times   []struct {
			Value string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Channels  []string `xml:"Channel"`
		Computers []string `xml:"Computer"`
	} `xml:"System"`
	Data []struct {
		Values []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// Parse accepts a single bounded native Event XML document. Nonremote or
// unrelated events retain their record identity but cannot enter counters.
func Parse(data []byte) (Record, error) {
	var r Record
	if len(data) == 0 || len(data) > maxXML {
		return r, fmt.Errorf("event_size")
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	var e eventXML
	if err := d.Decode(&e); err != nil {
		return r, fmt.Errorf("event_xml: %w", err)
	}
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return r, fmt.Errorf("event_xml")
		}
		if v, ok := t.(xml.CharData); !ok || strings.TrimSpace(string(v)) != "" {
			return r, fmt.Errorf("event_trailing_data")
		}
	}
	if e.XMLName.Local != "Event" || e.XMLName.Space != "http://schemas.microsoft.com/win/2004/08/events/event" || len(e.System) != 1 || len(e.Data) > 1 {
		return r, fmt.Errorf("event_structure")
	}
	s := e.System[0]
	if len(s.Provider) != 1 || len(s.IDs) != 1 || len(s.Records) != 1 || len(s.Times) != 1 || len(s.Channels) != 1 || s.Channels[0] != "Security" || len(s.Computers) != 1 {
		return r, fmt.Errorf("event_system")
	}
	id, err := strconv.ParseUint(s.Records[0], 10, 64)
	if err != nil || id == 0 {
		return r, fmt.Errorf("event_record_id")
	}
	at, err := time.Parse(time.RFC3339Nano, s.Times[0].Value)
	if err != nil {
		return r, fmt.Errorf("event_time")
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00%s\x00%s", s.Provider[0].Name, s.Provider[0].GUID, id, s.IDs[0], s.Times[0].Value, s.Computers[0])))
	r = Record{ID: id, Time: at, Fingerprint: hex.EncodeToString(sum[:])}
	if s.Provider[0].Name != provider || !strings.EqualFold(s.Provider[0].GUID, providerGUID) || (s.IDs[0] != "4624" && s.IDs[0] != "4625") {
		return r, nil
	}
	r.RawXML = string(data)
	r.EventID = s.IDs[0]
	if len(e.Data) != 1 || len(e.Data[0].Values) > 64 {
		return r, fmt.Errorf("event_fields")
	}
	fields := map[string]string{}
	for _, v := range e.Data[0].Values {
		if v.Name == "" || len(v.Name) > 128 || len(v.Value) > 1024 {
			return r, fmt.Errorf("event_field_size")
		}
		if _, ok := fields[v.Name]; ok {
			return r, fmt.Errorf("event_duplicate_field")
		}
		fields[v.Name] = v.Value
	}
	typ, err := strconv.Atoi(fields["LogonType"])
	if err != nil {
		return r, fmt.Errorf("event_logon_type")
	}
	if typ != 3 && typ != 10 {
		return r, nil
	}
	ip, err := netip.ParseAddr(fields["IpAddress"])
	if err != nil || ip.Zone() != "" {
		return r, nil
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return r, nil
	}
	user := fields["TargetUserName"]
	domain := fields["TargetDomainName"]
	if user == "" || user == "-" || len(user) > 256 || len(domain) > 256 || strings.ContainsRune(user+domain, 0) {
		return r, fmt.Errorf("event_account")
	}
	if domain != "" && domain != "-" {
		user = domain + "\\" + user
	}
	r.Attempt = &Attempt{IP: ip, Account: user, LogonType: typ, Failed: s.IDs[0] == "4625", Status: fields["Status"], SubStatus: fields["SubStatus"]}
	return r, nil
}
