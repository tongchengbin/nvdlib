package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vehemont/nvdlib-go/internal/nvdapi"
)

func newCVECmd(rf *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cve",
		Short: "Query CVEs",
	}

	cmd.AddCommand(newCVEGetCmd(rf))
	cmd.AddCommand(newCVESearchCmd(rf))
	return cmd
}

func newCVEGetCmd(rf *rootFlags) *cobra.Command {
	var cveID string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get a single CVE by CVE ID",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cveID == "" {
				return fmt.Errorf("--id is required")
			}

			client, err := newClientFromRootFlags(rf)
			if err != nil {
				return err
			}
			resp, err := client.GetCVE(context.Background(), cveID)
			if err != nil {
				return err
			}
			return writeOutput(cmd, rf, resp)
		},
	}

	cmd.Flags().StringVar(&cveID, "id", "", "CVE ID (e.g. CVE-2021-26855)")
	return cmd
}

func newCVESearchCmd(rf *rootFlags) *cobra.Command {
	var q nvdapi.CVESearchQuery

	cmd := &cobra.Command{
		Use:   "search",
		Short: "Search CVEs (NVD API v2)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := q.Validate(); err != nil {
				return err
			}

			client, err := newClientFromRootFlags(rf)
			if err != nil {
				return err
			}
			resp, err := client.SearchCVE(context.Background(), q)
			if err != nil {
				return err
			}
			return writeOutput(cmd, rf, resp)
		},
	}

	cmd.Flags().StringVar(&q.CVEID, "cve-id", "", "Filter by CVE ID")
	cmd.Flags().StringVar(&q.KeywordSearch, "keyword", "", "Search keywords (keywordSearch)")
	cmd.Flags().BoolVar(&q.KeywordExactMatch, "keyword-exact", false, "Exact keyword match (requires --keyword)")
	cmd.Flags().StringVar(&q.CVSSV3Severity, "cvss-v3-severity", "", "LOW|MEDIUM|HIGH|CRITICAL")
	cmd.Flags().StringVar(&q.CVSSV2Severity, "cvss-v2-severity", "", "LOW|MEDIUM|HIGH")
	cmd.Flags().StringVar(&q.CPEName, "cpe-name", "", "Filter by CPE name (cpeName)")
	cmd.Flags().BoolVar(&q.IsVulnerable, "is-vulnerable", false, "Require vulnerable CPE match (requires --cpe-name)")
	cmd.Flags().BoolVar(&q.NoRejected, "no-rejected", false, "Filter out rejected CVEs")
	cmd.Flags().StringVar(&q.PubStartDate, "pub-start", "", "Publish start date: 'YYYY-MM-DD HH:MM' or RFC3339")
	cmd.Flags().StringVar(&q.PubEndDate, "pub-end", "", "Publish end date: 'YYYY-MM-DD HH:MM' or RFC3339")
	cmd.Flags().StringVar(&q.LastModStartDate, "mod-start", "", "Last modified start date: 'YYYY-MM-DD HH:MM' or RFC3339")
	cmd.Flags().StringVar(&q.LastModEndDate, "mod-end", "", "Last modified end date: 'YYYY-MM-DD HH:MM' or RFC3339")
	cmd.Flags().IntVar(&q.Limit, "limit", 0, "Maximum total results to return (>=1). If >2000, auto-pagination is used")

	return cmd
}
