package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	proto "github.com/mental-lab/grumble/pkg/proto"
)

// Store persists scan results and pod inventory using PostgreSQL.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore connects to the given Postgres connection string and runs migrations.
func NewStore(ctx context.Context, connStr string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("opening db pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connecting to db: %w", err)
	}
	s := &Store{pool: pool}
	return s, s.migrate(ctx)
}

func (s *Store) Close() {
	s.pool.Close()
}

// Pool returns the connection pool for use by the API layer.
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS scan_results (
			id            TEXT PRIMARY KEY,
			cluster_id    TEXT NOT NULL,
			image         TEXT NOT NULL,
			image_digest  TEXT,
			vuln_count    INTEGER DEFAULT 0,
			critical      INTEGER DEFAULT 0,
			high          INTEGER DEFAULT 0,
			medium        INTEGER DEFAULT 0,
			low           INTEGER DEFAULT 0,
			vulns_json    JSONB,
			scanned_at    TIMESTAMPTZ,
			db_version    TEXT,
			image_labels  JSONB
		);

		CREATE TABLE IF NOT EXISTS pod_inventory (
			cluster_id   TEXT NOT NULL,
			namespace    TEXT NOT NULL,
			pod_name     TEXT NOT NULL,
			image        TEXT NOT NULL,
			image_digest TEXT,
			node         TEXT,
			phase        TEXT,
			updated_at   TIMESTAMPTZ,
			PRIMARY KEY (cluster_id, namespace, pod_name)
		);

		CREATE TABLE IF NOT EXISTS packages (
			image        TEXT NOT NULL,
			cluster_id   TEXT NOT NULL,
			name         TEXT NOT NULL,
			version      TEXT NOT NULL,
			type         TEXT,
			language     TEXT,
			location     TEXT,
			purl         TEXT,
			license      TEXT,
			scanned_at   TIMESTAMPTZ,
			PRIMARY KEY (image, cluster_id, name, version)
		);

		CREATE TABLE IF NOT EXISTS agent_heartbeats (
			agent_id  TEXT PRIMARY KEY,
			last_seen TIMESTAMPTZ
		);

		CREATE TABLE IF NOT EXISTS agent_tokens (
			cluster_id  TEXT NOT NULL,
			token_hash  TEXT NOT NULL UNIQUE,
			created_at  TIMESTAMPTZ NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_pkg_name     ON packages(name);
		CREATE INDEX IF NOT EXISTS idx_pkg_image    ON packages(image);
		CREATE INDEX IF NOT EXISTS idx_scan_cluster ON scan_results(cluster_id);
		CREATE INDEX IF NOT EXISTS idx_scan_image   ON scan_results(image);
		CREATE INDEX IF NOT EXISTS idx_pod_cluster  ON pod_inventory(cluster_id);
		CREATE INDEX IF NOT EXISTS idx_pod_image    ON pod_inventory(image);
	`)
	if err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}

	// Image catalog: one row per unique image+cluster joined with the latest scan.
	// Recreated on every startup to pick up definition changes.
	_, err = s.pool.Exec(ctx, `
		CREATE OR REPLACE VIEW image_catalog AS
		WITH latest_scans AS (
			SELECT image, cluster_id, MAX(scanned_at) AS max_at
			FROM scan_results GROUP BY image, cluster_id
		)
		SELECT
			p.image,
			p.cluster_id,
			MAX(p.image_digest)                                    AS image_digest,
			COUNT(DISTINCT p.namespace)                            AS namespace_count,
			COUNT(DISTINCT p.pod_name)                             AS pod_count,
			STRING_AGG(DISTINCT p.namespace, ',')                  AS namespaces,
			MIN(p.updated_at)                                      AS first_seen,
			MAX(p.updated_at)                                      AS last_seen,
			COALESCE(MAX(s.critical), 0)                           AS critical,
			COALESCE(MAX(s.high), 0)                               AS high,
			COALESCE(MAX(s.medium), 0)                             AS medium,
			COALESCE(MAX(s.low), 0)                                AS low,
			COALESCE(MAX(s.vuln_count), 0)                         AS total_vulns,
			CASE WHEN MAX(s.scanned_at) IS NOT NULL
				THEN 'scanned' ELSE 'pending' END                  AS scan_status,
			MAX(s.scanned_at)                                      AS scanned_at,
			COALESCE(MAX(s.image_labels::text)::jsonb, '{}'::jsonb) AS image_labels
		FROM pod_inventory p
		LEFT JOIN latest_scans ls ON ls.image = p.image AND ls.cluster_id = p.cluster_id
		LEFT JOIN scan_results s
			ON s.image = ls.image AND s.cluster_id = ls.cluster_id AND s.scanned_at = ls.max_at
		GROUP BY p.image, p.cluster_id
	`)
	return err
}

func (s *Store) SaveScanResult(ctx context.Context, r *proto.ScanResult) error {
	counts := countBySeverity(r.Vulns)
	vulnsJSON, _ := json.Marshal(r.Vulns)
	labelsJSON, _ := json.Marshal(r.ImageLabels)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO scan_results
			(id, cluster_id, image, image_digest, vuln_count, critical, high, medium, low, vulns_json, scanned_at, db_version, image_labels)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (id) DO UPDATE SET
			cluster_id   = EXCLUDED.cluster_id,
			image        = EXCLUDED.image,
			image_digest = EXCLUDED.image_digest,
			vuln_count   = EXCLUDED.vuln_count,
			critical     = EXCLUDED.critical,
			high         = EXCLUDED.high,
			medium       = EXCLUDED.medium,
			low          = EXCLUDED.low,
			vulns_json   = EXCLUDED.vulns_json,
			scanned_at   = EXCLUDED.scanned_at,
			db_version   = EXCLUDED.db_version,
			image_labels = EXCLUDED.image_labels`,
		r.ScanId, r.ClusterId, r.Image, r.ImageDigest,
		len(r.Vulns), counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"],
		vulnsJSON,
		time.Unix(r.ScannedAt, 0),
		r.GrypeDbVersion,
		labelsJSON,
	)
	if err != nil {
		return err
	}

	if len(r.Packages) > 0 {
		return s.savePackages(ctx, r.Image, r.ClusterId, r.Packages, time.Unix(r.ScannedAt, 0))
	}
	return nil
}

func (s *Store) savePackages(ctx context.Context, image, clusterID string, pkgs []*proto.Package, scannedAt time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `DELETE FROM packages WHERE image = $1 AND cluster_id = $2`, image, clusterID); err != nil {
		return err
	}

	for _, p := range pkgs {
		_, err := tx.Exec(ctx, `
			INSERT INTO packages
				(image, cluster_id, name, version, type, language, location, purl, license, scanned_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (image, cluster_id, name, version) DO UPDATE SET
				type       = EXCLUDED.type,
				language   = EXCLUDED.language,
				location   = EXCLUDED.location,
				purl       = EXCLUDED.purl,
				license    = EXCLUDED.license,
				scanned_at = EXCLUDED.scanned_at`,
			image, clusterID, p.Name, p.Version, p.Type, p.Language, p.Location, p.Purl, p.License, scannedAt,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) SaveInventory(ctx context.Context, clusterID string, inv *proto.PodInventory) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	for _, pod := range inv.Pods {
		_, err := tx.Exec(ctx, `
			INSERT INTO pod_inventory
				(cluster_id, namespace, pod_name, image, image_digest, node, phase, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (cluster_id, namespace, pod_name) DO UPDATE SET
				image        = EXCLUDED.image,
				image_digest = EXCLUDED.image_digest,
				node         = EXCLUDED.node,
				phase        = EXCLUDED.phase,
				updated_at   = EXCLUDED.updated_at`,
			clusterID, pod.Namespace, pod.Name, pod.Image, pod.ImageDigest,
			pod.Node, pod.Phase, time.Now(),
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) UpdateHeartbeat(ctx context.Context, agentID string, ts int64) {
	s.pool.Exec(ctx, `
		INSERT INTO agent_heartbeats (agent_id, last_seen) VALUES ($1, $2)
		ON CONFLICT (agent_id) DO UPDATE SET last_seen = EXCLUDED.last_seen`,
		agentID, time.Unix(ts, 0),
	) //nolint:errcheck
}

// LookupToken returns the cluster ID for a given token hash, or error if not found.
func (s *Store) LookupToken(ctx context.Context, tokenHash string) (string, error) {
	var clusterID string
	err := s.pool.QueryRow(ctx,
		`SELECT cluster_id FROM agent_tokens WHERE token_hash = $1`, tokenHash,
	).Scan(&clusterID)
	if err == pgx.ErrNoRows {
		return "", fmt.Errorf("token not found")
	}
	return clusterID, err
}

// RegisterToken stores a hashed token for the given cluster ID.
func (s *Store) RegisterToken(ctx context.Context, clusterID, tokenHash string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO agent_tokens (cluster_id, token_hash, created_at) VALUES ($1, $2, $3)`,
		clusterID, tokenHash, time.Now(),
	)
	return err
}

func countBySeverity(vulns []*proto.Vulnerability) map[string]int {
	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, v := range vulns {
		key := strings.ToUpper(v.Severity)
		if _, ok := counts[key]; ok {
			counts[key]++
		}
	}
	return counts
}
