// Package scap delegates XCCDF/OVAL semantics to a pinned native interpreter.
// The Agent validates transport and execution boundaries, never translates
// standard rules into a smaller proprietary check language.
package scap

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	MaxArchive  = 2 << 20
	MaxExpanded = 32 << 20
	MaxRules    = 2000
	xccdf11     = "http://checklists.nist.gov/xccdf/1.1"
	xccdf12     = "http://checklists.nist.gov/xccdf/1.2"
	catalogNS   = "urn:oasis:names:tc:entity:xmlns:xml:catalog"
)

type Manifest struct {
	SchemaVersion    int    `json:"schemaVersion"`
	Code             string `json:"code"`
	Version          string `json:"version"`
	Name             string `json:"name"`
	OSType           int    `json:"osType"`
	OSVersionPattern string `json:"osVersionPattern"`
	BenchmarkFile    string `json:"benchmarkFile"`
	BenchmarkID      string `json:"benchmarkId"`
	ProfileID        string `json:"profileId"`
}
type Content struct {
	Manifest Manifest
	SHA256   string
	Rules    []string
	Files    map[string][]byte
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$`)
var packagePath = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]*$`)

func safePath(name string) bool {
	if len(name) > 512 || !packagePath.MatchString(name) {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
func Digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func ParseContent(archive []byte) (*Content, error) {
	if len(archive) == 0 || len(archive) > MaxArchive {
		return nil, errors.New("scap_archive_limit")
	}
	z, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil || len(z.File) == 0 || len(z.File) > 128 {
		return nil, errors.New("scap_archive_invalid")
	}
	c := &Content{SHA256: Digest(archive), Files: map[string][]byte{}}
	expanded := 0
	for _, entry := range z.File {
		name := entry.Name
		if !safePath(name) || !entry.Mode().IsRegular() || c.Files[name] != nil ||
			(name != "alinksec-scap.json" && !strings.HasSuffix(name, ".xml")) {
			return nil, errors.New("scap_archive_path")
		}
		reader, err := entry.Open()
		if err != nil {
			return nil, errors.New("scap_archive_invalid")
		}
		data, err := io.ReadAll(io.LimitReader(reader, int64(MaxExpanded-expanded+1)))
		reader.Close()
		expanded += len(data)
		if err != nil || expanded > MaxExpanded {
			return nil, errors.New("scap_archive_limit")
		}
		c.Files[name] = data
	}
	manifest := c.Files["alinksec-scap.json"]
	if len(manifest) == 0 || len(manifest) > 16384 || !utf8.Valid(manifest) || strictManifest(manifest, &c.Manifest) != nil {
		return nil, errors.New("scap_manifest_invalid")
	}
	m := c.Manifest
	if m.SchemaVersion != 1 || (m.OSType != 1 && m.OSType != 2) || !identifier.MatchString(m.Code) ||
		!identifier.MatchString(m.Version) || !identifier.MatchString(m.BenchmarkID) || !identifier.MatchString(m.ProfileID) ||
		strings.TrimSpace(m.Name) == "" || utf8.RuneCountInString(m.Name) > 256 || len(m.OSVersionPattern) == 0 ||
		utf8.RuneCountInString(m.OSVersionPattern) > 256 || len(c.Files[m.BenchmarkFile]) == 0 || !strings.HasSuffix(m.BenchmarkFile, ".xml") {
		return nil, errors.New("scap_manifest_invalid")
	}
	if _, err := regexp.Compile(m.OSVersionPattern); err != nil {
		return nil, errors.New("scap_manifest_invalid")
	}
	benchmarks := 0
	selected := false
	for name, data := range c.Files {
		if !strings.HasSuffix(name, ".xml") {
			continue
		}
		info, err := inspectXML(data)
		if err != nil {
			return nil, err
		}
		benchmarks += info.benchmarks
		if name == m.BenchmarkFile && info.benchmarkID == m.BenchmarkID {
			selected = info.profiles[m.ProfileID]
			c.Rules = info.rules
		}
		for _, ref := range info.refs {
			if strings.HasPrefix(ref, "#") {
				if !info.ids[strings.TrimPrefix(ref, "#")] {
					return nil, errors.New("scap_reference_missing")
				}
				continue
			}
			file := strings.SplitN(ref, "#", 2)[0]
			if !safePath(file) {
				return nil, errors.New("scap_reference_external")
			}
			if c.Files[path.Join(path.Dir(name), file)] == nil && info.catalog[file] == "" {
				return nil, errors.New("scap_reference_missing")
			}
		}
		for _, ref := range info.catalog {
			if !strings.HasPrefix(ref, "#") || !info.ids[strings.TrimPrefix(ref, "#")] {
				return nil, errors.New("scap_reference_missing")
			}
		}
	}
	if benchmarks != 1 || !selected || len(c.Rules) == 0 || len(c.Rules) > MaxRules {
		return nil, errors.New("scap_selection_invalid")
	}
	return c, nil
}

func strictManifest(data []byte, out *Manifest) error {
	scan := json.NewDecoder(bytes.NewReader(data))
	if first, err := scan.Token(); err != nil || first != json.Delim('{') {
		return errors.New("object required")
	}
	seen := map[string]bool{}
	for scan.More() {
		token, err := scan.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return errors.New("duplicate field")
		}
		seen[name] = true
		if err := scan.Decode(new(json.RawMessage)); err != nil {
			return err
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing content")
	}
	return nil
}

type xmlInfo struct {
	benchmarks  int
	benchmarkID string
	rules       []string
	profiles    map[string]bool
	ids         map[string]bool
	refs        []string
	catalog     map[string]string
}

func isXCCDF(space string) bool { return space == xccdf11 || space == xccdf12 }
func attr(start xml.StartElement, name string) string {
	for _, a := range start.Attr {
		if a.Name.Local == name && a.Name.Space == "" {
			return a.Value
		}
	}
	return ""
}
func inspectXML(data []byte) (*xmlInfo, error) {
	if len(data) == 0 || len(data) > MaxExpanded || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("scap_xml_invalid")
	}
	info := &xmlInfo{profiles: map[string]bool{}, ids: map[string]bool{}, catalog: map[string]string{}}
	d := xml.NewDecoder(bytes.NewReader(data))
	depth, count, benchmarkDepth, roots := 0, 0, 0, 0
	rules := map[string]bool{}
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("scap_xml_invalid")
		}
		switch t := token.(type) {
		case xml.Directive:
			return nil, errors.New("scap_xml_external_entity")
		case xml.ProcInst:
			if t.Target != "xml" {
				return nil, errors.New("scap_xml_invalid")
			}
		case xml.StartElement:
			if depth == 0 {
				roots++
				if roots > 1 {
					return nil, errors.New("scap_xml_invalid")
				}
			}
			depth++
			count++
			if depth > 128 || count > 150000 {
				return nil, errors.New("scap_xml_limit")
			}
			local, space := t.Name.Local, t.Name.Space
			if space == "http://www.w3.org/2001/XInclude" {
				return nil, errors.New("scap_xml_external_entity")
			}
			for _, a := range t.Attr {
				if a.Name.Space == "http://www.w3.org/XML/1998/namespace" && a.Name.Local == "base" {
					return nil, errors.New("scap_reference_external")
				}
				if a.Name.Local == "href" && local != "reference" && local != "metadata" {
					info.refs = append(info.refs, a.Value)
				}
			}
			if id := attr(t, "id"); id != "" {
				info.ids[id] = true
			}
			lower := strings.ToLower(local)
			if local == "check-content" || strings.Contains(lower, "shellcommand") || strings.Contains(lower, "powershell") || strings.Contains(lower, "cmdlet") || strings.HasPrefix(lower, "sql_") || strings.HasPrefix(lower, "sql57_") || isXCCDF(space) && local == "fix" {
				return nil, errors.New("scap_executable_content")
			}
			if isXCCDF(space) && local == "check" {
				system := attr(t, "system")
				if system != "http://oval.mitre.org/XMLSchema/oval-definitions-5" && system != "http://scap.nist.gov/schema/ocil/2" && system != "http://scap.nist.gov/schema/ocil/2.0" {
					return nil, errors.New("scap_check_system_unsupported")
				}
			}
			if space == catalogNS && local == "uri" {
				name, ref := attr(t, "name"), attr(t, "uri")
				if !safePath(name) || !strings.HasPrefix(ref, "#") || len(ref) < 2 || info.catalog[name] != "" && info.catalog[name] != ref {
					return nil, errors.New("scap_reference_external")
				}
				info.catalog[name] = ref
			}
			if isXCCDF(space) && local == "Benchmark" {
				info.benchmarks++
				info.benchmarkID = attr(t, "id")
				benchmarkDepth = depth
			}
			if isXCCDF(space) && benchmarkDepth > 0 {
				if local == "Rule" {
					id := attr(t, "id")
					if !identifier.MatchString(id) || rules[id] || len(info.rules) >= MaxRules {
						return nil, errors.New("scap_rule_invalid")
					}
					rules[id] = true
					info.rules = append(info.rules, id)
				}
				if local == "Profile" {
					id := attr(t, "id")
					if !identifier.MatchString(id) || info.profiles[id] {
						return nil, errors.New("scap_profile_invalid")
					}
					info.profiles[id] = true
				}
			}
		case xml.EndElement:
			if depth == benchmarkDepth {
				benchmarkDepth = 0
			}
			depth--
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(t)) != "" {
				return nil, errors.New("scap_xml_invalid")
			}
		}
	}
	if roots != 1 {
		return nil, errors.New("scap_xml_invalid")
	}
	return info, nil
}
