package nvdapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	cveEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	cpeEndpoint = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
)

type ClientOptions struct {
	HTTPClient *http.Client
	APIKey     string
	Delay      time.Duration
	ProxyURL   *url.URL
}

type Client struct {
	hc    *http.Client
	key   string
	delay time.Duration
}

func NewClient(opts ClientOptions) *Client {
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	if opts.ProxyURL != nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Proxy = http.ProxyURL(opts.ProxyURL)
		hc.Transport = tr
	}

	d := opts.Delay
	if d == 0 {
		d = 6 * time.Second
	}

	return &Client{hc: hc, key: opts.APIKey, delay: d}
}

func (c *Client) GetCVE(ctx context.Context, cveID string) (map[string]any, error) {
	q := CVESearchQuery{CVEID: cveID}
	q.Limit = 0
	return c.SearchCVE(ctx, q)
}

func (c *Client) SearchCVE(ctx context.Context, q CVESearchQuery) (map[string]any, error) {
	params, err := q.ToParams()
	if err != nil {
		return nil, err
	}
	return c.getJSONPaged(ctx, cveEndpoint, params, q.Limit, "vulnerabilities")
}

func (c *Client) SearchCPE(ctx context.Context, q CPESearchQuery) (map[string]any, error) {
	params, err := q.ToParams()
	if err != nil {
		return nil, err
	}
	return c.getJSONPaged(ctx, cpeEndpoint, params, q.Limit, "products")
}


func (c *Client) doJSON(ctx context.Context, endpoint string, params url.Values) (map[string]any, error) {
	u := endpoint + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	if c.key != "" {
		req.Header.Set("apiKey", c.key)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("nvd api error: status=%d body=%s", resp.StatusCode, string(body))
	}

	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if msg, ok := out["message"].(string); ok && msg != "" {
		return nil, errors.New(msg)
	}
	return out, nil
}

func (c *Client) getJSONPaged(ctx context.Context, endpoint string, params url.Values, limit int, listKey string) (map[string]any, error) {
	pageSize := 2000
	if limit > 0 && limit < pageSize {
		pageSize = limit
	}
	params.Set("resultsPerPage", strconv.Itoa(pageSize))

	out, err := c.doJSON(ctx, endpoint, params)
	if err != nil {
		return nil, err
	}
	time.Sleep(c.delay)

	// No need to paginate unless user requests more than a single page.
	if limit <= 2000 {
		return out, nil
	}

	// Extract pagination metadata.
	startIndex, _ := asInt(out["startIndex"])
	resultsPerPage, _ := asInt(out["resultsPerPage"])
	totalResults, _ := asInt(out["totalResults"])
	if resultsPerPage <= 0 {
		resultsPerPage = pageSize
	}

	items, _ := asAnySlice(out[listKey])
	maxWanted := totalResults
	if limit > 0 && limit < maxWanted {
		maxWanted = limit
	}
	if maxWanted <= len(items) {
		out[listKey] = items[:maxWanted]
		return out, nil
	}

	for {
		startIndex += resultsPerPage
		if startIndex >= totalResults {
			break
		}
		if len(items) >= maxWanted {
			break
		}

		params.Set("startIndex", strconv.Itoa(startIndex))
		params.Set("resultsPerPage", strconv.Itoa(resultsPerPage))
		batch, err := c.doJSON(ctx, endpoint, params)
		if err != nil {
			return nil, err
		}
		time.Sleep(c.delay)

		batchItems, _ := asAnySlice(batch[listKey])
		if len(batchItems) == 0 {
			break
		}
		items = append(items, batchItems...)
		if len(items) >= maxWanted {
			items = items[:maxWanted]
			break
		}
	}

	out[listKey] = items
	return out, nil
}

func asInt(v any) (int, bool) {
	switch t := v.(type) {
	case float64:
		return int(t), true
	case int:
		return t, true
	case int64:
		return int(t), true
	case string:
		i, err := strconv.Atoi(t)
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}

func asAnySlice(v any) ([]any, bool) {
	arr, ok := v.([]any)
	return arr, ok
}
