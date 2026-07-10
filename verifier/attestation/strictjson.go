package attestation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// Strict JSON decoding for attestation documents.
//
// encoding/json (v1) is lenient in ways that break the v3 "strict schema"
// contract across SDK implementations, each a parser-differential vector
// between verifiers in different languages:
//
//   - member names match Go fields case-insensitively ("FORMAT" fills
//     Format, and DisallowUnknownFields does not object),
//   - duplicate object members are silently accepted (last one wins; other
//     parsers may keep the first),
//   - invalid UTF-8 is replaced with U+FFFD instead of rejected.
//
// strictUnmarshal closes these by running a syntactic validation pass over
// the input before the normal decode: member names must exactly match a
// schema field's json tag, duplicate member names are rejected in every
// object (including inside opaque json.RawMessage subtrees, whose bytes an
// attacker controls), and the input must be valid UTF-8.
//
// TODO(go1.27): these are the default semantics of encoding/json/v2. Once
// that package is stable in the standard library (expected Go 1.27), delete
// this file and reimplement strictUnmarshal as a jsontext.Decoder plus
// json.UnmarshalDecode(dec, v, json.RejectUnknownMembers(true)) and a
// trailing-data check. See sdk-flywheel FUTURE_PRS_GO.md §0.
//
// Known limitation (shared with v1 elsewhere): escaped lone surrogates such
// as "\uD800" inside strings are still replaced with U+FFFD rather than
// rejected; the raw-byte UTF-8 check cannot see them. json/v2 fixes this.

// strictUnmarshal decodes JSON into v, rejecting unknown members
// (case-sensitively), duplicate member names anywhere in the input,
// invalid UTF-8, and trailing data.
func strictUnmarshal(data []byte, v any) error {
	if err := validateStrictJSON(data, reflect.TypeOf(v)); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing data")
	}
	return nil
}

var rawMessageType = reflect.TypeOf(json.RawMessage(nil))

// validateStrictJSON walks the JSON syntactically, checking member names
// against the schema type without decoding any values.
func validateStrictJSON(data []byte, schema reflect.Type) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("input is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkStrictValue(dec, schemaType(schema)); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing data")
	}
	return nil
}

// schemaType normalizes a schema node: pointers are dereferenced, and types
// that decode opaquely (json.RawMessage) become nil, meaning "no member-name
// schema; duplicate-name checks only".
func schemaType(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == rawMessageType {
		return nil
	}
	return t
}

func walkStrictValue(dec *json.Decoder, schema reflect.Type) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		// Scalar: type conformance is checked by the subsequent decode.
		return nil
	}
	switch delim {
	case '{':
		return walkStrictObject(dec, schema)
	case '[':
		var elem reflect.Type
		if schema != nil && (schema.Kind() == reflect.Slice || schema.Kind() == reflect.Array) {
			elem = schemaType(schema.Elem())
		}
		for dec.More() {
			if err := walkStrictValue(dec, elem); err != nil {
				return err
			}
		}
		_, err = dec.Token() // closing ']'
		return err
	}
	return nil
}

func walkStrictObject(dec *json.Decoder, schema reflect.Type) error {
	// fields is non-nil for struct schemas: members must exactly match a
	// json tag. valueSchema propagates through map schemas, whose member
	// names are data (e.g. captured HTTP headers), not schema.
	var fields map[string]reflect.Type
	var valueSchema reflect.Type
	if schema != nil {
		switch schema.Kind() {
		case reflect.Struct:
			fields = structFieldSchemas(schema)
		case reflect.Map:
			valueSchema = schemaType(schema.Elem())
		}
	}
	seen := make(map[string]bool)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("object member name is not a string")
		}
		if seen[key] {
			return fmt.Errorf("duplicate object member %q", key)
		}
		seen[key] = true
		child := valueSchema
		if fields != nil {
			ft, known := fields[key]
			if !known {
				return fmt.Errorf("unknown object member %q", key)
			}
			child = ft
		}
		if err := walkStrictValue(dec, child); err != nil {
			return err
		}
	}
	_, err := dec.Token() // closing '}'
	return err
}

// structFieldSchemas maps exact JSON member names to field schema types.
func structFieldSchemas(t reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		name := f.Name
		if tag, ok := f.Tag.Lookup("json"); ok {
			if tag == "-" {
				continue
			}
			if tagName, _, _ := strings.Cut(tag, ","); tagName != "" {
				name = tagName
			}
		}
		fields[name] = schemaType(f.Type)
	}
	return fields
}
