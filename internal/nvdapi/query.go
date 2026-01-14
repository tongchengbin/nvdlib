package nvdapi

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

var ErrInvalidDate = fmt.Errorf("invalid date")

// NVDLib accepts either datetime object or a string with format '%Y-%m-%d %H:%M'.
// For CLI we accept either that format or RFC3339.
func parseDate(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02 15:04", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("%w: %q (use RFC3339 or 'YYYY-MM-DD HH:MM')", ErrInvalidDate, s)
}

type CVESearchQuery struct {
	CPEName           string
	CVEID             string
	CVSSV2Severity    string
	CVSSV3Severity    string
	IsVulnerable      bool
	KeywordExactMatch bool
	KeywordSearch     string
	NoRejected        bool
	PubStartDate      string
	PubEndDate        string
	LastModStartDate  string
	LastModEndDate    string
	Limit             int
}

func (q CVESearchQuery) Validate() error {
	if q.KeywordExactMatch && q.KeywordSearch == "" {
		return fmt.Errorf("--keyword-exact requires --keyword")
	}
	if q.IsVulnerable && q.CPEName == "" {
		return fmt.Errorf("--is-vulnerable requires --cpe-name")
	}
	if (q.PubStartDate != "") != (q.PubEndDate != "") {
		return fmt.Errorf("--pub-start and --pub-end must be used together")
	}
	if (q.LastModStartDate != "") != (q.LastModEndDate != "") {
		return fmt.Errorf("--mod-start and --mod-end must be used together")
	}
	if q.Limit != 0 && q.Limit < 1 {
		return fmt.Errorf("--limit must be >= 1")
	}
	if q.CVSSV2Severity != "" {
		s := strings.ToUpper(q.CVSSV2Severity)
		if s != "LOW" && s != "MEDIUM" && s != "HIGH" {
			return fmt.Errorf("--cvss-v2-severity must be LOW|MEDIUM|HIGH")
		}
	}
	if q.CVSSV3Severity != "" {
		s := strings.ToUpper(q.CVSSV3Severity)
		if s != "LOW" && s != "MEDIUM" && s != "HIGH" && s != "CRITICAL" {
			return fmt.Errorf("--cvss-v3-severity must be LOW|MEDIUM|HIGH|CRITICAL")
		}
	}
	if q.PubStartDate != "" {
		if _, err := parseDate(q.PubStartDate); err != nil {
			return err
		}
		if _, err := parseDate(q.PubEndDate); err != nil {
			return err
		}
	}
	if q.LastModStartDate != "" {
		if _, err := parseDate(q.LastModStartDate); err != nil {
			return err
		}
		if _, err := parseDate(q.LastModEndDate); err != nil {
			return err
		}
	}
	return nil
}

func (q CVESearchQuery) ToParams() (url.Values, error) {
	params := url.Values{}

	if q.CPEName != "" {
		params.Set("cpeName", q.CPEName)
	}
	if q.CVEID != "" {
		params.Set("cveId", q.CVEID)
	}
	if q.KeywordSearch != "" {
		params.Set("keywordSearch", q.KeywordSearch)
	}
	if q.KeywordExactMatch {
		// nvdlib passes 'keywordExactMatch' with no value for CVE
		params.Set("keywordExactMatch", "")
	}
	if q.CVSSV2Severity != "" {
		params.Set("cvssV2Severity", strings.ToUpper(q.CVSSV2Severity))
	}
	if q.CVSSV3Severity != "" {
		params.Set("cvssV3Severity", strings.ToUpper(q.CVSSV3Severity))
	}
	if q.IsVulnerable {
		params.Set("isVulnerable", "true")
	}
	if q.NoRejected {
		// nvdlib passes 'noRejected' with no value
		params.Set("noRejected", "")
	}

	if q.PubStartDate != "" {
		t1, err := parseDate(q.PubStartDate)
		if err != nil {
			return nil, err
		}
		t2, err := parseDate(q.PubEndDate)
		if err != nil {
			return nil, err
		}
		params.Set("pubStartDate", t1.Format(time.RFC3339))
		params.Set("pubEndDate", t2.Format(time.RFC3339))
	}
	if q.LastModStartDate != "" {
		t1, err := parseDate(q.LastModStartDate)
		if err != nil {
			return nil, err
		}
		t2, err := parseDate(q.LastModEndDate)
		if err != nil {
			return nil, err
		}
		params.Set("lastModStartDate", t1.Format(time.RFC3339))
		params.Set("lastModEndDate", t2.Format(time.RFC3339))
	}

	// resultsPerPage / startIndex are handled by the client pagination layer

	return params, nil
}

type CPESearchQuery struct {
	CPENameID         string
	CPEMatchString    string
	KeywordExactMatch bool
	KeywordSearch     string
	LastModStartDate  string
	LastModEndDate    string
	MatchCriteriaID   string
	Limit             int
}

func (q CPESearchQuery) Validate() error {
	if q.KeywordExactMatch && q.KeywordSearch == "" {
		return fmt.Errorf("--keyword-exact requires --keyword")
	}
	if (q.LastModStartDate != "") != (q.LastModEndDate != "") {
		return fmt.Errorf("--mod-start and --mod-end must be used together")
	}
	if q.Limit != 0 && q.Limit < 1 {
		return fmt.Errorf("--limit must be >= 1")
	}
	if q.LastModStartDate != "" {
		if _, err := parseDate(q.LastModStartDate); err != nil {
			return err
		}
		if _, err := parseDate(q.LastModEndDate); err != nil {
			return err
		}
	}
	return nil
}

func (q CPESearchQuery) ToParams() (url.Values, error) {
	params := url.Values{}

	if q.CPENameID != "" {
		params.Set("cpeNameId", q.CPENameID)
	}
	if q.CPEMatchString != "" {
		params.Set("cpeMatchString", q.CPEMatchString)
	}
	if q.KeywordSearch != "" {
		params.Set("keywordSearch", q.KeywordSearch)
	}
	if q.KeywordExactMatch {
		params.Set("keywordExactMatch", "true")
	}
	if q.LastModStartDate != "" {
		t1, err := parseDate(q.LastModStartDate)
		if err != nil {
			return nil, err
		}
		t2, err := parseDate(q.LastModEndDate)
		if err != nil {
			return nil, err
		}
		params.Set("lastModStartDate", t1.Format(time.RFC3339))
		params.Set("lastModEndDate", t2.Format(time.RFC3339))
	}
	if q.MatchCriteriaID != "" {
		params.Set("matchCriteriaId", q.MatchCriteriaID)
	}
	// resultsPerPage / startIndex are handled by the client pagination layer
	return params, nil
}
