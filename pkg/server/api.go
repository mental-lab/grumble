package server

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

// API exposes an HTTP JSON API for Grafana to query.
// Uses the Grafana JSON datasource plugin format.
type API struct {
	store *Store
	log   *zap.Logger
}

func NewAPI(store *Store, log *zap.Logger) *API {
	return &API{store: store, log: log}
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.health)
	mux.HandleFunc("/hotspots", a.hotspots)
	mux.HandleFunc("/clusters", a.clusters)
	mux.HandleFunc("/inventory", a.inventory)
	mux.HandleFunc("/images", a.images)
	mux.HandleFunc("/packages", a.packages)
	return mux
}

// health satisfies the Grafana JSON datasource /  check
// packages answers "which images use package X?" queries.
// Query params:
//   ?name=log4j         — exact or partial package name match
//   ?type=java          — filter by ecosystem (java, python, npm, apk, deb, rpm)
//   ?cluster=prod       — filter by cluster
//   ?version_lt=2.15.0  — packages with version less than (string prefix match)
func (a *API) packages(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	pkgType := r.URL.Query().Get("type")
	cluster := r.URL.Query().Get("cluster")

	query := `
		SELECT
			p.name, p.version, p.type, p.language, p.purl, p.license,
			p.image, p.cluster_id,
			COUNT(DISTINCT pi.pod_name) as pod_count,
			COUNT(DISTINCT pi.namespace) as namespace_count,
			p.scanned_at
		FROM packages p
		LEFT JOIN pod_inventory pi ON pi.image = p.image AND pi.cluster_id = p.cluster_id
		WHERE 1=1`
	args := []interface{}{}

	if name != "" {
		query += ` AND p.name LIKE ?`
		args = append(args, "%"+name+"%")
	}
	if pkgType != "" {
		query += ` AND p.type = ?`
		args = append(args, pkgType)
	}
	if cluster != "" {
		query += ` AND p.cluster_id = ?`
		args = append(args, cluster)
	}

	query += ` GROUP BY p.name, p.version, p.image, p.cluster_id ORDER BY pod_count DESC, p.name`

	rows, err := a.store.db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type PackageEntry struct {
		Name           string `json:"name"`
		Version        string `json:"version"`
		Type           string `json:"type"`
		Language       string `json:"language"`
		Purl           string `json:"purl"`
		License        string `json:"license"`
		Image          string `json:"image"`
		ClusterID      string `json:"cluster_id"`
		PodCount       int    `json:"pod_count"`
		NamespaceCount int    `json:"namespace_count"`
		ScannedAt      string `json:"scanned_at"`
	}

	var results []PackageEntry
	for rows.Next() {
		var e PackageEntry
		rows.Scan(
			&e.Name, &e.Version, &e.Type, &e.Language, &e.Purl, &e.License,
			&e.Image, &e.ClusterID, &e.PodCount, &e.NamespaceCount, &e.ScannedAt,
		)
		results = append(results, e)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// hotspots returns images ranked by (critical+high vulns) × (number of pods using the image)
// This is the core "where do we focus?" view.
func (a *API) hotspots(w http.ResponseWriter, r *http.Request) {
	rows, err := a.store.db.Query(`
		SELECT
			s.image,
			s.cluster_id,
			s.critical,
			s.high,
			s.medium,
			s.low,
			s.scanned_at,
			COUNT(p.pod_name) as pod_count,
			(s.critical * 10 + s.high * 3 + s.medium) * COUNT(p.pod_name) as risk_score
		FROM scan_results s
		LEFT JOIN pod_inventory p ON p.image = s.image AND p.cluster_id = s.cluster_id
		GROUP BY s.image, s.cluster_id
		ORDER BY risk_score DESC
		LIMIT 50
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Hotspot struct {
		Image     string `json:"image"`
		ClusterID string `json:"cluster_id"`
		Critical  int    `json:"critical"`
		High      int    `json:"high"`
		Medium    int    `json:"medium"`
		Low       int    `json:"low"`
		PodCount  int    `json:"pod_count"`
		RiskScore int    `json:"risk_score"`
		ScannedAt string `json:"scanned_at"`
	}

	var results []Hotspot
	for rows.Next() {
		var h Hotspot
		if err := rows.Scan(&h.Image, &h.ClusterID, &h.Critical, &h.High, &h.Medium, &h.Low, &h.ScannedAt, &h.PodCount, &h.RiskScore); err != nil {
			continue
		}
		results = append(results, h)
	}

	json.NewEncoder(w).Encode(results)
}

func (a *API) clusters(w http.ResponseWriter, r *http.Request) {
	rows, err := a.store.db.Query(`
		SELECT cluster_id, COUNT(DISTINCT image) as images, SUM(critical) as critical, SUM(high) as high
		FROM scan_results
		GROUP BY cluster_id
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type ClusterSummary struct {
		ClusterID string `json:"cluster_id"`
		Images    int    `json:"images"`
		Critical  int    `json:"critical"`
		High      int    `json:"high"`
	}

	var results []ClusterSummary
	for rows.Next() {
		var c ClusterSummary
		rows.Scan(&c.ClusterID, &c.Images, &c.Critical, &c.High)
		results = append(results, c)
	}

	json.NewEncoder(w).Encode(results)
}

// images returns the full image catalog — every unique image running across
// all clusters, with pod/namespace counts and scan status.
// Optional query params: ?cluster=<id>, ?scan_status=pending|scanned
func (a *API) images(w http.ResponseWriter, r *http.Request) {
	cluster := r.URL.Query().Get("cluster")
	scanStatus := r.URL.Query().Get("scan_status")

	query := `
		SELECT
			image, image_digest, cluster_id,
			namespace_count, pod_count, namespaces,
			first_seen, last_seen,
			critical, high, medium, low, total_vulns,
			scan_status, scanned_at
		FROM image_catalog
		WHERE 1=1`
	args := []interface{}{}

	if cluster != "" {
		query += ` AND cluster_id = ?`
		args = append(args, cluster)
	}
	if scanStatus != "" {
		query += ` AND scan_status = ?`
		args = append(args, scanStatus)
	}
	query += ` ORDER BY total_vulns DESC, pod_count DESC`

	rows, err := a.store.db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type ImageEntry struct {
		Image          string `json:"image"`
		ImageDigest    string `json:"image_digest"`
		ClusterID      string `json:"cluster_id"`
		NamespaceCount int    `json:"namespace_count"`
		PodCount       int    `json:"pod_count"`
		Namespaces     string `json:"namespaces"`
		FirstSeen      string `json:"first_seen"`
		LastSeen       string `json:"last_seen"`
		Critical       int    `json:"critical"`
		High           int    `json:"high"`
		Medium         int    `json:"medium"`
		Low            int    `json:"low"`
		TotalVulns     int    `json:"total_vulns"`
		ScanStatus     string `json:"scan_status"`
		ScannedAt      string `json:"scanned_at"`
	}

	var results []ImageEntry
	for rows.Next() {
		var e ImageEntry
		rows.Scan(
			&e.Image, &e.ImageDigest, &e.ClusterID,
			&e.NamespaceCount, &e.PodCount, &e.Namespaces,
			&e.FirstSeen, &e.LastSeen,
			&e.Critical, &e.High, &e.Medium, &e.Low, &e.TotalVulns,
			&e.ScanStatus, &e.ScannedAt,
		)
		results = append(results, e)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (a *API) inventory(w http.ResponseWriter, r *http.Request) {
	cluster := r.URL.Query().Get("cluster")
	query := `SELECT cluster_id, namespace, pod_name, image, phase FROM pod_inventory`
	args := []interface{}{}
	if cluster != "" {
		query += ` WHERE cluster_id = ?`
		args = append(args, cluster)
	}

	rows, err := a.store.db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Pod struct {
		ClusterID string `json:"cluster_id"`
		Namespace string `json:"namespace"`
		PodName   string `json:"pod_name"`
		Image     string `json:"image"`
		Phase     string `json:"phase"`
	}

	var results []Pod
	for rows.Next() {
		var p Pod
		rows.Scan(&p.ClusterID, &p.Namespace, &p.PodName, &p.Image, &p.Phase)
		results = append(results, p)
	}

	json.NewEncoder(w).Encode(results)
}
