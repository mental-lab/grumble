package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"
	"go.uber.org/zap"

	proto "github.com/mental-lab/grumble/pkg/proto"
)

// Scanner wraps Grype to scan container images for vulnerabilities
type Scanner struct {
	distConfig v6dist.Config
	instConfig v6inst.Config
	log        *zap.Logger
	clusterID  string
}

func NewScanner(clusterID string, grypeDBDir string, log *zap.Logger) (*Scanner, error) {
	distCfg := v6dist.Config{
		LatestURL: "https://grype.anchore.io/databases",
	}
	instCfg := v6inst.Config{
		DBRootDir:        grypeDBDir,
		ValidateChecksum: true,
	}
	return &Scanner{
		distConfig: distCfg,
		instConfig: instCfg,
		log:        log,
		clusterID:  clusterID,
	}, nil
}

// Scan runs Grype against a container image and returns a ScanResult
func (s *Scanner) Scan(ctx context.Context, scanID, image string) (*proto.ScanResult, error) {
	s.log.Info("scanning image", zap.String("image", image), zap.String("scanID", scanID))

	vulnProvider, dbStatus, err := grype.LoadVulnerabilityDB(s.distConfig, s.instConfig, true)
	if err != nil {
		return nil, fmt.Errorf("loading grype db: %w", err)
	}
	defer vulnProvider.Close()

	packages, pkgContext, _, err := pkg.Provide(image, pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			SBOMOptions: syft.DefaultCreateSBOMConfig(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("generating SBOM for %s: %w", image, err)
	}

	vulnMatcher := &grype.VulnerabilityMatcher{
		VulnerabilityProvider: vulnProvider,
		Matchers:              matcher.NewDefaultMatchers(matcher.Config{}),
	}
	remainingMatches, _, err := vulnMatcher.FindMatches(packages, pkgContext)
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
		severity := ""
		description := ""
		if m.Vulnerability.Metadata != nil {
			severity = m.Vulnerability.Metadata.Severity
			description = m.Vulnerability.Metadata.Description
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
