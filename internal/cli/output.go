package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)


func writeOutput(cmd *cobra.Command, rf *rootFlags, v any) error {
	switch strings.ToLower(strings.TrimSpace(rf.Output)) {
	case "", "json":
		var (
			b   []byte
			err error
		)
		if rf.Pretty {
			b, err = json.MarshalIndent(v, "", "  ")
		} else {
			b, err = json.Marshal(v)
		}
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err

	case "jsonl":
		items, err := extractJSONLItems(v)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetEscapeHTML(false)
		for _, it := range items {
			if err := enc.Encode(it); err != nil {
				return err
			}
		}
		return nil

	default:
		return fmt.Errorf("unsupported --output=%q (supported: json, jsonl)", rf.Output)
	}
}

func extractJSONLItems(v any) ([]any, error) {
	root, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("jsonl output expects an object response")
	}

	// CVE: vulnerabilities[].cve
	if raw, ok := root["vulnerabilities"]; ok {
		arr, ok := raw.([]any)
		if !ok {
			return nil, fmt.Errorf("unexpected vulnerabilities type")
		}
		out := make([]any, 0, len(arr))
		for _, el := range arr {
			m, ok := el.(map[string]any)
			if ok {
				if inner, ok := m["cve"]; ok {
					out = append(out, inner)
					continue
				}
			}
			out = append(out, el)
		}
		return out, nil
	}

	// CPE: products[].cpe
	if raw, ok := root["products"]; ok {
		arr, ok := raw.([]any)
		if !ok {
			return nil, fmt.Errorf("unexpected products type")
		}
		out := make([]any, 0, len(arr))
		for _, el := range arr {
			m, ok := el.(map[string]any)
			if ok {
				if inner, ok := m["cpe"]; ok {
					out = append(out, inner)
					continue
				}
			}
			out = append(out, el)
		}
		return out, nil
	}

	// CPE Match: matchStrings[].matchString
	if raw, ok := root["matchStrings"]; ok {
		arr, ok := raw.([]any)
		if !ok {
			return nil, fmt.Errorf("unexpected matchStrings type")
		}
		out := make([]any, 0, len(arr))
		for _, el := range arr {
			m, ok := el.(map[string]any)
			if ok {
				if inner, ok := m["matchString"]; ok {
					out = append(out, inner)
					continue
				}
			}
			out = append(out, el)
		}
		return out, nil
	}

	return nil, fmt.Errorf("jsonl output is only supported for list responses (vulnerabilities/products/matchStrings)")
}
