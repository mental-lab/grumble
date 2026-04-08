package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"
	"github.com/google/go-containerregistry/pkg/crane"
	"go.uber.org/zap"

	proto "github.com/mental-lab/grumble/pkg/proto"
)

// Scanner wraps Grype to scan container images for vulnerabilities
type Scanner struct {
	distConfig   v6dist.Config
	instConfig   v6inst.Config
	log          *zap.Logger
	clusterID    string
	vulnProvider vulnerability.Provider
	dbVersion    string
}

func NewScanner(clusterID string, grypeDBDir string, log *zap.Logger) (*Scanner, error) {
	distCfg := v6dist.Config{
		LatestURL: "https://grype.anchore.io/databases",
	}
	instCfg := v6inst.Config{
		DBRootDir:        grypeDBDir,
		ValidateChecksum: true,
	}

	vulnProvider, dbStatus, err := grype.LoadVulnerabilityDB(distCfg, instCfg, true)
	if err != nil {
		return nil, fmt.Errorf("loading grype db: %w", err)
	}

	return &Scanner{
		distConfig:   distCfg,
		instConfig:   instCfg,
		log:          log,
		clusterID:    clusterID,
		vulnProvider: vulnProvider,
		dbVersion:    dbStatus.SchemaVersion,
	}, nil
}

// Close releases resources held by the Scanner (the Grype vulnerability DB).
func (s *Scanner) Close() {
	if err := s.vulnProvider.Close(); err != nil {
		s.log.Warn("closing vuln provider", zap.Error(err))
	}
}

// Scan runs Grype against a container image and returns a ScanResult
func (s *Scanner) Scan(ctx context.Context, scanID, image string) (*proto.ScanResult, error) {
	s.log.Info("scanning image", zap.String("image", image), zap.String("scanID", scanID))

	packages, pkgContext, _, err := pkg.Provide(image, pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			SBOMOptions: syft.DefaultCreateSBOMConfig(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("generating SBOM for %s: %w", image, err)
	}

	vulnMatcher := &grype.VulnerabilityMatcher{
		VulnerabilityProvider: s.vulnProvider,
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
		GrypeDbVersion: s.dbVersion,
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

	result.ImageLabels = fetchImageLabels(image)

	s.log.Info("scan complete",
		zap.String("image", image),
		zap.Int("vulns", len(result.Vulns)),
		zap.Int("packages", len(result.Packages)))

	return result, nil
}

// fetchImageLabels retrieves OCI image labels from the registry.
// Returns an empty map on any error — labels are best-effort and must never
// fail a scan.
func fetchImageLabels(image string) map[string]string {
	cfg, err := crane.Config(image)
	if err != nil {
		return map[string]string{}
	}
	var imgCfg struct {
		Config struct {
			Labels map[string]string
		}
	}
	if err := json.Unmarshal(cfg, &imgCfg); err != nil {
		return map[string]string{}
	}
	if imgCfg.Config.Labels == nil {
		return map[string]string{}
	}
	return imgCfg.Config.Labels
}

func fixedIn(v vulnerability.Vulnerability) string {
	if len(v.Fix.Versions) > 0 {
		return v.Fix.Versions[0]
	}
	return ""
}
