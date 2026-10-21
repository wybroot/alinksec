package scap

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

var Outcomes = map[string]bool{"pass": true, "fail": true, "error": true, "unknown": true,
	"notapplicable": true, "notchecked": true, "notselected": true, "informational": true, "fixed": true}

// ParseResults accepts one fresh, complete XCCDF result bound to the dispatched
// benchmark and profile. It intentionally exports no OVAL collected host values.
func ParseResults(data []byte, content *Content) ([]*pb.ScapRuleResult, []*pb.ScapScore, error) {
	invalid := errors.New("scap_result_invalid")
	if len(data) == 0 || len(data) > 8<<20 || content == nil {
		return nil, nil, invalid
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	depth, elements, resultDepth, resultCount, profiles := 0, 0, 0, 0, 0
	benchmarkBound := false
	expected := map[string]bool{}
	for _, id := range content.Rules {
		expected[id] = true
	}
	seen := map[string]bool{}
	scoreSystems := map[string]bool{}
	var rules []*pb.ScapRuleResult
	var scores []*pb.ScapScore
	var current *pb.ScapRuleResult
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, invalid
		}
		switch t := token.(type) {
		case xml.Directive:
			return nil, nil, invalid
		case xml.ProcInst:
			if t.Target != "xml" {
				return nil, nil, invalid
			}
		case xml.StartElement:
			depth++
			elements++
			if depth > 128 || elements > 150000 {
				return nil, nil, invalid
			}
			if !isXCCDF(t.Name.Space) {
				continue
			}
			switch t.Name.Local {
			case "Benchmark":
				if attr(t, "id") != content.Manifest.BenchmarkID {
					return nil, nil, invalid
				}
				benchmarkBound = true
			case "TestResult":
				resultCount++
				if resultCount != 1 {
					return nil, nil, invalid
				}
				resultDepth = depth
			case "benchmark":
				if resultDepth > 0 && attr(t, "id") == content.Manifest.BenchmarkID {
					benchmarkBound = true
				}
			case "profile":
				if resultDepth > 0 {
					profiles++
					if attr(t, "idref") != content.Manifest.ProfileID || profiles > 1 {
						return nil, nil, invalid
					}
				}
			case "rule-result":
				if resultDepth == 0 {
					return nil, nil, invalid
				}
				id := attr(t, "idref")
				if current != nil || !expected[id] || seen[id] {
					return nil, nil, invalid
				}
				seen[id] = true
				weight := 1.0
				if raw := attr(t, "weight"); raw != "" {
					weight, err = strconv.ParseFloat(raw, 64)
					if err != nil {
						return nil, nil, invalid
					}
				}
				if !finite(weight) || weight < 0 || weight > 1e6 {
					return nil, nil, invalid
				}
				current = &pb.ScapRuleResult{RuleId: id, Weight: weight}
			case "result":
				if current != nil {
					var value string
					if current.Result != "" || decoder.DecodeElement(&value, &t) != nil || !Outcomes[strings.TrimSpace(value)] {
						return nil, nil, invalid
					}
					current.Result = strings.TrimSpace(value)
					depth--
				}
			case "score":
				if resultDepth > 0 {
					system := attr(t, "system")
					maximum, err := strconv.ParseFloat(attr(t, "maximum"), 64)
					if err != nil || system == "" || len(system) > 256 || scoreSystems[system] || len(scores) >= 16 || !finite(maximum) || maximum < 0 || maximum > 1e6 {
						return nil, nil, invalid
					}
					var raw string
					if decoder.DecodeElement(&raw, &t) != nil {
						return nil, nil, invalid
					}
					depth--
					value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
					if err != nil || !finite(value) || value < 0 || value > maximum {
						return nil, nil, invalid
					}
					scoreSystems[system] = true
					scores = append(scores, &pb.ScapScore{System: system, Value: value, Maximum: maximum})
				}
			}
		case xml.EndElement:
			if isXCCDF(t.Name.Space) && t.Name.Local == "rule-result" {
				if current == nil || !Outcomes[current.Result] {
					return nil, nil, invalid
				}
				rules = append(rules, current)
				current = nil
			}
			if depth == resultDepth {
				resultDepth = 0
			}
			depth--
		}
	}
	if resultCount != 1 || profiles != 1 || !benchmarkBound || len(rules) != len(expected) || len(scores) == 0 {
		return nil, nil, invalid
	}
	return rules, scores, nil
}
func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }
