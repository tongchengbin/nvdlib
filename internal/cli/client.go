package cli

import (
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/vehemont/nvdlib-go/internal/nvdapi"
)

func newClientFromRootFlags(rf *rootFlags) (*nvdapi.Client, error) {
	hc := &http.Client{Timeout: 30 * time.Second}

	var proxyURL *url.URL
	if rf.Proxy != "" {
		u, err := url.Parse(rf.Proxy)
		if err != nil {
			return nil, err
		}
		proxyURL = u
	}

	apiKey := rf.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("NVD_API_KEY")
	}

	delay := rf.Delay
	if delay == 0 {
		// Match nvdlib default behavior
		delay = 6
	}

	return nvdapi.NewClient(nvdapi.ClientOptions{
		HTTPClient: hc,
		APIKey:     apiKey,
		Delay:      time.Duration(float64(time.Second) * delay),
		ProxyURL:   proxyURL,
	}), nil
}
