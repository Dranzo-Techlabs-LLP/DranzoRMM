package posture

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Limits of the property list reader.
const (
	plistMaxDepth = 32
	plistMaxNodes = 200_000
)

// IsBinaryPlist reports whether data is a binary property list (which must
// be converted with `plutil -convert xml1` before ParsePlist can read it).
func IsBinaryPlist(data []byte) bool { return bytes.HasPrefix(data, []byte("bplist")) }

// ParsePlist reads an XML property list into Go values: dict ->
// map[string]any, array -> []any, string -> string, date -> time.Time,
// integer -> int64, real -> float64, true / false -> bool, data -> string
// (the base64 text).
func ParsePlist(data []byte) (any, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	p := &plistParser{d: d}
	for {
		tok, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("plist: no content")
			}
			return nil, fmt.Errorf("plist: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local == "plist" {
			continue
		}
		return p.value(se, 0)
	}
}

type plistParser struct {
	d     *xml.Decoder
	nodes int
}

// text reads the character data up to the end of the current element.
func (p *plistParser) text() (string, error) {
	var sb strings.Builder
	for {
		tok, err := p.d.Token()
		if err != nil {
			return "", fmt.Errorf("plist: %w", err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.EndElement:
			return sb.String(), nil
		case xml.StartElement:
			return "", errors.New("plist: unexpected element inside a scalar")
		}
	}
}

func (p *plistParser) value(se xml.StartElement, depth int) (any, error) {
	if depth > plistMaxDepth {
		return nil, errors.New("plist: nested too deeply")
	}
	p.nodes++
	if p.nodes > plistMaxNodes {
		return nil, errors.New("plist: too many elements")
	}
	switch se.Name.Local {
	case "dict":
		m := map[string]any{}
		key, haveKey := "", false
		for {
			tok, err := p.d.Token()
			if err != nil {
				return nil, fmt.Errorf("plist: %w", err)
			}
			switch t := tok.(type) {
			case xml.EndElement:
				return m, nil
			case xml.StartElement:
				if t.Name.Local == "key" {
					k, err := p.text()
					if err != nil {
						return nil, err
					}
					key, haveKey = k, true
					continue
				}
				v, err := p.value(t, depth+1)
				if err != nil {
					return nil, err
				}
				if haveKey {
					m[key] = v
					haveKey = false
				}
			}
		}
	case "array":
		a := []any{}
		for {
			tok, err := p.d.Token()
			if err != nil {
				return nil, fmt.Errorf("plist: %w", err)
			}
			switch t := tok.(type) {
			case xml.EndElement:
				return a, nil
			case xml.StartElement:
				v, err := p.value(t, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
		}
	case "string", "data":
		return p.text()
	case "date":
		s, err := p.text()
		if err != nil {
			return nil, err
		}
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("plist: invalid date %q", s)
		}
		return t.UTC(), nil
	case "integer":
		s, err := p.text()
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(strings.TrimSpace(s), 0, 64)
		if err != nil {
			return nil, fmt.Errorf("plist: invalid integer %q", s)
		}
		return n, nil
	case "real":
		s, err := p.text()
		if err != nil {
			return nil, err
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return nil, fmt.Errorf("plist: invalid real %q", s)
		}
		return f, nil
	case "true":
		if _, err := p.text(); err != nil {
			return nil, err
		}
		return true, nil
	case "false":
		if _, err := p.text(); err != nil {
			return nil, err
		}
		return false, nil
	}
	return nil, fmt.Errorf("plist: unknown element <%s>", se.Name.Local)
}

// PlistDict parses an XML property list whose root is a dictionary.
func PlistDict(data []byte) (map[string]any, error) {
	v, err := ParsePlist(data)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("plist: root is not a dictionary")
	}
	return m, nil
}

// PlistString returns the string value of a top-level key ("" if absent).
func PlistString(data []byte, key string) string {
	m, err := PlistDict(data)
	if err != nil {
		return ""
	}
	s, _ := m[key].(string)
	return strings.TrimSpace(s)
}

// PlistBool returns the boolean value of a top-level key (integers 0 / 1
// are accepted). ok is false when the key is absent or of another type.
func PlistBool(data []byte, key string) (value, ok bool) {
	m, err := PlistDict(data)
	if err != nil {
		return false, false
	}
	switch v := m[key].(type) {
	case bool:
		return v, true
	case int64:
		return v != 0, true
	}
	return false, false
}

// PlistInt returns the integer value of a top-level key.
func PlistInt(data []byte, key string) (int64, bool) {
	m, err := PlistDict(data)
	if err != nil {
		return 0, false
	}
	switch v := m[key].(type) {
	case int64:
		return v, true
	case float64:
		return int64(v), true
	}
	return 0, false
}
