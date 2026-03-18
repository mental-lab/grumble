package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"

	proto "github.com/mental-lab/grumble/pkg/proto"
)

// Store persists scan results and pod inventory using SQLite.
// For production deployments, swap for Postgres.
type Store struct {
	db *sql.DB
}

func NewStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}
	s := &Store{db: db}
	return s, s.migrate()
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
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
			vulns_json    TEXT,
			scanned_at    DATETIME,
			db_version    TEXT
		);

		CREATE TABLE IF NOT EXISTS pod_inventory (
			cluster_id  TEXT NOT NULL,
			namespace   TEXT NOT NULL,
			pod_name    TEXT NOT NULL,
			image       TEXT NOT NULL,
			image_digest TEXT,
			node        TEXT,
			phase       TEXT,
			updated_at  DATETIME,
			PRIMARY KEY (cluster_id, namespace, pod_name)
		);

		CREATE TABLE IF NOT EXISTS agent_heartbeats (
			agent_id    TEXT PRIMARY KEY,
			last_seen   DATETIME
		);

		CREATE INDEX IF NOT EXISTS idx_scan_cluster ON scan_results(cluster_id);
		CREATE INDEX IF NOT EXISTS idx_scan_image   ON scan_results(image);
		CREATE INDEX IF NOT EXISTS idx_pod_cluster  ON pod_inventory(cluster_id);
	`)
	return err
}

func (s *Store) SaveScanResult(r *proto.ScanResult) error {
	counts := countBySeverity(r.Vulns)
	vulnsJSON, _ := json.Marshal(r.Vulns)

	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO scan_results
			(id, cluster_id, image, image_digest, vuln_count, critical, high, medium, low, vulns_json, scanned_at, db_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ScanId, r.ClusterId, r.Image, r.ImageDigest,
		len(r.Vulns), counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"],
		string(vulnsJSON),
		time.Unix(r.ScannedAt, 0),
		r.GrypeDbVersion,
	)
	return err
}

func (s *Store) SaveInventory(clusterID string, inv *proto.PodInventory) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, pod := range inv.Pods {
		_, err := tx.Exec(`
			INSERT OR REPLACE INTO pod_inventory
				(cluster_id, namespace, pod_name, image, image_digest, node, phase, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			clusterID, pod.Namespace, pod.Name, pod.Image, pod.ImageDigest,
			pod.Node, pod.Phase, time.Now(),
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) UpdateHeartbeat(agentID string, ts int64) {
	s.db.Exec(`INSERT OR REPLACE INTO agent_heartbeats (agent_id, last_seen) VALUES (?, ?)`,
		agentID, time.Unix(ts, 0))
}

func countBySeverity(vulns []*proto.Vulnerability) map[string]int {
	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, v := range vulns {
		if _, ok := counts[v.Severity]; ok {
			counts[v.Severity]++
		}
	}
	return counts
}
