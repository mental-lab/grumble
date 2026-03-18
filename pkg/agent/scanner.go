package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
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

	packages, pkgContext, _, err := pkg.Provide(image, pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{},
	})
	if err != nil {
		return nil, fmt.Errorf("generating SBOM for %s: %w", image, err)
	}

	vulnMatcher := grype.DefaultVulnerabilityMatcher(*store)
	remainingMatches, _, err := vulnMatcher.FindMatches(packages, pkgContext)
	if err != nil {
		return nil, fmt.Errorf("finding vulnerabilities: %w", err)
	}

	result := &proto.ScanResult{
		ScanId:         scanID,
		Image:          image,
		ClusterId:      s.clusterID,
		ScannedAt:      time.Now().Unix(),
		GrypeDbVersion: fmt.Sprintf("%d", dbStatus.SchemaVersion),
	}

	for _, m := range remainingMatches.Sorted() {
		severity := ""
		description := ""
		if meta, err := store.GetMetadata(m.Vulnerability.ID, m.Vulnerability.Namespace); err == nil && meta != nil {
			severity = meta.Severity
			description = meta.Description
		}
		result.Vulns = append(result.Vulns, &proto.Vulnerability{
			Id:          m.Vulnerability.ID,
			PackageName: m.Package.Name,
			Version:     m.Package.Version,
			FixedIn:     fixedIn(m.Vulnerability),
			Severity:    severity,
			Description: description,
		})
	}

	// Extract the full package list from the SBOM
	seen := map[string]bool{}
	for _, p := range packages {
		key := p.Name + "@" + p.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		loc := ""
		if p.Locations.ToSlice() != nil && len(p.Locations.ToSlice()) > 0 {
			loc = p.Locations.ToSlice()[0].RealPath
		}

		result.Packages = append(result.Packages, &proto.Package{
			Name:     p.Name,
			Version:  p.Version,
			Type:     string(p.Type),
			Language: string(p.Language),
			Location: loc,
			Purl:     p.PURL,
		})
	}

	s.log.Info("scan complete",
		zap.String("image", image),
		zap.Int("vulns", len(result.Vulns)),
		zap.Int("packages", len(result.Packages)))

	return result, nil
}

func fixedIn(v vulnerability.Vulnerability) string {
	if len(v.Fix.Versions) > 0 {
		return v.Fix.Versions[0]
	}
	return ""
}
