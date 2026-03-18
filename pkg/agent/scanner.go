package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/source"
	"go.uber.org/zap"

	proto "github.com/mental-lab/grumble/pkg/proto"
)

// Scanner wraps Grype to scan container images for vulnerabilities
type Scanner struct {
	dbConfig  db.Config
	log       *zap.Logger
	clusterID string
}

func NewScanner(clusterID string, grypeDBDir string, log *zap.Logger) (*Scanner, error) {
	cfg := db.Config{
		DBRootDir:           grypeDBDir,
		ListingURL:          "https://toolbox-data.anchore.io/grype/databases/listing.json",
		ValidateByHashOnGet: true,
	}
	return &Scanner{
		dbConfig:  cfg,
		log:       log,
		clusterID: clusterID,
	}, nil
}

// Scan runs Grype against a container image and returns a ScanResult
func (s *Scanner) Scan(ctx context.Context, scanID, image string) (*proto.ScanResult, error) {
	s.log.Info("scanning image", zap.String("image", image), zap.String("scanID", scanID))

	store, dbStatus, _, err := grype.LoadVulnerabilityDB(s.dbConfig, true)
	if err != nil {
		return nil, fmt.Errorf("loading grype db: %w", err)
	}

	packages, pkgContext, err := pkg.Provide(image, pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			RegistryOptions: &source.RegistryOptions{},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("generating SBOM for %s: %w", image, err)
	}

	matcher := grype.DefaultGrypeIgnoreRules
	remainingMatches, ignoredMatches, err := grype.FindVulnerabilities(
		vulnerability.NewProviderFromStore(store),
		pkgContext,
		match.NewDefaultMatcher(match.MatcherConfig{}),
		packages,
		matcher,
	)
	_ = ignoredMatches

	if err != nil {
		return nil, fmt.Errorf("finding vulnerabilities: %w", err)
	}

	result := &proto.ScanResult{
		ScanId:         scanID,
		Image:          image,
		ClusterId:      s.clusterID,
		ScannedAt:      time.Now().Unix(),
		GrypeDbVersion: dbStatus.SchemaVersion,
	}

	for _, m := range remainingMatches.Sorted() {
		result.Vulns = append(result.Vulns, &proto.Vulnerability{
			Id:          m.Vulnerability.ID,
			PackageName: m.Package.Name,
			Version:     m.Package.Version,
			FixedIn:     fixedIn(m.Vulnerability),
			Severity:    m.Vulnerability.Severity,
			Description: m.Vulnerability.Description,
		})
	}

	s.log.Info("scan complete",
		zap.String("image", image),
		zap.Int("vulns", len(result.Vulns)))

	return result, nil
}

func fixedIn(v vulnerability.Vulnerability) string {
	if len(v.Fix.Versions) > 0 {
		return v.Fix.Versions[0]
	}
	return ""
}
