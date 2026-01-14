package cli

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/vehemont/nvdlib-go/internal/nvdapi"
)

func newCPECmd(rf *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cpe",
		Short: "Query CPEs",
	}

	cmd.AddCommand(newCPESearchCmd(rf))
	return cmd
}

func newCPESearchCmd(rf *rootFlags) *cobra.Command {
	var q nvdapi.CPESearchQuery

	cmd := &cobra.Command{
		Use:   "search",
		Short: "Search CPEs (NVD API v2)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := q.Validate(); err != nil {
				return err
			}

			client, err := newClientFromRootFlags(rf)
			if err != nil {
				return err
			}
			resp, err := client.SearchCPE(context.Background(), q)
			if err != nil {
				return err
			}
			return writeOutput(cmd, rf, resp)
		},
	}

	cmd.Flags().StringVar(&q.CPENameID, "cpe-name-id", "", "CPE name UUID")
	cmd.Flags().StringVar(&q.CPEMatchString, "cpe-match", "", "CPE match string (partial is allowed)")
	cmd.Flags().StringVar(&q.KeywordSearch, "keyword", "", "Keyword search")
	cmd.Flags().BoolVar(&q.KeywordExactMatch, "keyword-exact", false, "Exact keyword match (requires --keyword)")
	cmd.Flags().StringVar(&q.LastModStartDate, "mod-start", "", "Last modified start date: 'YYYY-MM-DD HH:MM' or RFC3339")
	cmd.Flags().StringVar(&q.LastModEndDate, "mod-end", "", "Last modified end date: 'YYYY-MM-DD HH:MM' or RFC3339")
	cmd.Flags().StringVar(&q.MatchCriteriaID, "match-criteria-id", "", "Match criteria UUID")
	cmd.Flags().IntVar(&q.Limit, "limit", 0, "Maximum total results to return (>=1). If >2000, auto-pagination is used")

	return cmd
}
