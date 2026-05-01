package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

// API exposes an HTTP JSON API for Grafana to query.
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
	mux.HandleFunc("/stats", a.stats)
	mux.HandleFunc("/hotspots", a.hotspots)
	mux.HandleFunc("/clusters", a.clusters)
	mux.HandleFunc("/inventory", a.inventory)
	mux.HandleFunc("/images", a.images)
	mux.HandleFunc("/images/export", a.imagesExport)
	mux.HandleFunc("/packages", a.packages)
	mux.HandleFunc("/vulns", a.vulns)
	return mux
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// stats returns aggregate counts for Grafana stat panels.
func (a *API) stats(w http.ResponseWriter, r *http.Request) {
	var result struct {
		Clusters      int `json:"clusters"`
		ImagesScanned int `json:"images_scanned"`
		CriticalTotal int `json:"critical_total"`
		HighTotal     int `json:"high_total"`
		MediumTotal   int `json:"medium_total"`
		PodsTracked   int `json:"pods_tracked"`
	}

	ctx := r.Context()
	pool := a.store.Pool()

	pool.QueryRow(ctx, `SELECT COUNT(DISTINCT cluster_id) FROM scan_results`).Scan(&result.Clusters)                      //nolint:errcheck
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM pod_inventory`).Scan(&result.PodsTracked)                                   //nolint:errcheck

	pool.QueryRow(ctx, `
		WITH latest AS (SELECT image, cluster_id, MAX(scanned_at) AS max_at FROM scan_results GROUP BY image, cluster_id)
		SELECT COUNT(*) FROM scan_results s
		JOIN latest ON s.image=latest.image AND s.cluster_id=latest.cluster_id AND s.scanned_at=latest.max_at
	`).Scan(&result.ImagesScanned) //nolint:errcheck

	pool.QueryRow(ctx, `
		WITH latest AS (SELECT image, cluster_id, MAX(scanned_at) AS max_at FROM scan_results GROUP BY image, cluster_id)
		SELECT COALESCE(SUM(s.critical),0), COALESCE(SUM(s.high),0), COALESCE(SUM(s.medium),0)
		FROM scan_results s
		JOIN latest ON s.image=latest.image AND s.cluster_id=latest.cluster_id AND s.scanned_at=latest.max_at
	`).Scan(&result.CriticalTotal, &result.HighTotal, &result.MediumTotal) //nolint:errcheck

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result) //nolint:errcheck
}

// packages answers "which images use package X?" queries.
// Query params:
//
//	?name=log4j    — partial package name match
//	?type=java     — filter by ecosystem
//	?cluster=prod  — filter by cluster
func (a *API) packages(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	pkgType := r.URL.Query().Get("type")
	cluster := r.URL.Query().Get("cluster")

	query := `
		SELECT
			p.name, p.version, p.type, p.language, p.purl, p.license,
			p.image, p.cluster_id,
			COUNT(DISTINCT pi.pod_name) AS pod_count,
			COUNT(DISTINCT pi.namespace) AS namespace_count,
			p.scanned_at
		FROM packages p
		LEFT JOIN pod_inventory pi ON pi.image = p.image AND pi.cluster_id = p.cluster_id
		WHERE 1=1`
	args := []any{}
	idx := 1

	if name != "" {
		query += ` AND p.name LIKE $` + strconv.Itoa(idx)
		args = append(args, "%"+name+"%")
		idx++
	}
	if pkgType != "" {
		query += ` AND p.type = $` + strconv.Itoa(idx)
		args = append(args, pkgType)
		idx++
	}
	if cluster != "" {
		query += ` AND p.cluster_id = $` + strconv.Itoa(idx)
		args = append(args, cluster)
	}
	query += ` GROUP BY p.name, p.version, p.image, p.cluster_id ORDER BY pod_count DESC, p.name`

	rows, err := a.store.Pool().Query(r.Context(), query, args...)
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

	results := []PackageEntry{}
	for rows.Next() {
		var e PackageEntry
		rows.Scan(&e.Name, &e.Version, &e.Type, &e.Language, &e.Purl, &e.License, //nolint:errcheck
			&e.Image, &e.ClusterID, &e.PodCount, &e.NamespaceCount, &e.ScannedAt)
		results = append(results, e)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results) //nolint:errcheck
}

// vulns returns individual vulnerability details.
// Query params: ?image=<image>, ?cluster=<id>, ?severity=Critical
func (a *API) vulns(w http.ResponseWriter, r *http.Request) {
	image := r.URL.Query().Get("image")
	cluster := r.URL.Query().Get("cluster")
	severity := r.URL.Query().Get("severity")

	query := `
		SELECT
			s.image, s.cluster_id,
			v->>'id'           AS vuln_id,
			v->>'package_name' AS package_name,
			v->>'version'      AS version,
			v->>'severity'     AS severity,
			v->>'fixed_in'     AS fixed_in,
			v->>'description'  AS description
		FROM scan_results s,
			jsonb_array_elements(s.vulns_json) AS v
		WHERE 1=1`
	args := []any{}
	idx := 1

	if image != "" {
		query += ` AND s.image LIKE $` + strconv.Itoa(idx)
		args = append(args, "%"+image+"%")
		idx++
	}
	if cluster != "" {
		query += ` AND s.cluster_id = $` + strconv.Itoa(idx)
		args = append(args, cluster)
		idx++
	}
	if severity != "" {
		query += ` AND v->>'severity' = $` + strconv.Itoa(idx)
		args = append(args, severity)
	}
	query += `
		ORDER BY
			CASE v->>'severity'
				WHEN 'Critical' THEN 1
				WHEN 'High'     THEN 2
				WHEN 'Medium'   THEN 3
				WHEN 'Low'      THEN 4
				ELSE 5
			END, s.image`

	rows, err := a.store.Pool().Query(r.Context(), query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type VulnEntry struct {
		Image       string `json:"image"`
		ClusterID   string `json:"cluster_id"`
		VulnID      string `json:"vuln_id"`
		PackageName string `json:"package_name"`
		Version     string `json:"version"`
		Severity    string `json:"severity"`
		FixedIn     string `json:"fixed_in"`
		Description string `json:"description"`
	}

	results := []VulnEntry{}
	for rows.Next() {
		var v VulnEntry
		rows.Scan(&v.Image, &v.ClusterID, &v.VulnID, &v.PackageName, &v.Version, &v.Severity, &v.FixedIn, &v.Description) //nolint:errcheck
		results = append(results, v)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results) //nolint:errcheck
}

// hotspots returns images ranked by risk × blast radius.
func (a *API) hotspots(w http.ResponseWriter, r *http.Request) {
	rows, err := a.store.Pool().Query(r.Context(), `
		WITH latest AS (
			SELECT image, cluster_id, MAX(scanned_at) AS max_at
			FROM scan_results GROUP BY image, cluster_id
		)
		SELECT
			s.image, s.cluster_id,
			s.critical, s.high, s.medium, s.low,
			s.scanned_at,
			COUNT(DISTINCT p.pod_name) AS pod_count,
			(s.critical * 10 + s.high * 3 + s.medium) * COUNT(DISTINCT p.pod_name) AS risk_score
		FROM scan_results s
		JOIN latest ON s.image = latest.image AND s.cluster_id = latest.cluster_id AND s.scanned_at = latest.max_at
		LEFT JOIN pod_inventory p ON p.image = s.image AND p.cluster_id = s.cluster_id
		GROUP BY s.image, s.cluster_id, s.critical, s.high, s.medium, s.low, s.scanned_at
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

	results := []Hotspot{}
	for rows.Next() {
		var h Hotspot
		if err := rows.Scan(&h.Image, &h.ClusterID, &h.Critical, &h.High, &h.Medium, &h.Low, &h.ScannedAt, &h.PodCount, &h.RiskScore); err != nil {
			continue
		}
		results = append(results, h)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results) //nolint:errcheck
}

func (a *API) clusters(w http.ResponseWriter, r *http.Request) {
	rows, err := a.store.Pool().Query(r.Context(), `
		WITH latest AS (
			SELECT image, cluster_id, MAX(scanned_at) AS max_at
			FROM scan_results GROUP BY image, cluster_id
		)
		SELECT s.cluster_id, COUNT(DISTINCT s.image) AS images, SUM(s.critical) AS critical, SUM(s.high) AS high
		FROM scan_results s
		JOIN latest ON s.image = latest.image AND s.cluster_id = latest.cluster_id AND s.scanned_at = latest.max_at
		GROUP BY s.cluster_id
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

	results := []ClusterSummary{}
	for rows.Next() {
		var c ClusterSummary
		rows.Scan(&c.ClusterID, &c.Images, &c.Critical, &c.High) //nolint:errcheck
		results = append(results, c)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results) //nolint:errcheck
}

// images returns the full image catalog.
// Optional query params: ?cluster=<id>, ?scan_status=pending|scanned, ?source=chainguard
func (a *API) images(w http.ResponseWriter, r *http.Request) {
	entries, err := a.queryImages(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries) //nolint:errcheck
}

// imagesExport returns the image catalog as a CSV download.
func (a *API) imagesExport(w http.ResponseWriter, r *http.Request) {
	entries, err := a.queryImages(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="images.csv"`)

	cw := csv.NewWriter(w)
	cw.Write([]string{ //nolint:errcheck
		"image", "image_digest", "cluster_id",
		"namespace_count", "pod_count", "namespaces",
		"first_seen", "last_seen",
		"critical", "high", "medium", "low", "total_vulns",
		"scan_status", "scanned_at", "is_chainguard",
	})
	for _, e := range entries {
		cw.Write([]string{ //nolint:errcheck
			e.Image, e.ImageDigest, e.ClusterID,
			fmt.Sprintf("%d", e.NamespaceCount),
			fmt.Sprintf("%d", e.PodCount),
			e.Namespaces, e.FirstSeen, e.LastSeen,
			fmt.Sprintf("%d", e.Critical),
			fmt.Sprintf("%d", e.High),
			fmt.Sprintf("%d", e.Medium),
			fmt.Sprintf("%d", e.Low),
			fmt.Sprintf("%d", e.TotalVulns),
			e.ScanStatus, e.ScannedAt,
			fmt.Sprintf("%v", e.IsChainguard),
		})
	}
	cw.Flush()
}

// ImageEntry is a single row from the image catalog view.
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
	ImageLabels    string `json:"image_labels"`
	IsChainguard   bool   `json:"is_chainguard"`
}

func (a *API) queryImages(r *http.Request) ([]ImageEntry, error) {
	cluster := r.URL.Query().Get("cluster")
	scanStatus := r.URL.Query().Get("scan_status")
	source := r.URL.Query().Get("source")

	query := `
		SELECT
			image, image_digest, cluster_id,
			namespace_count, pod_count, namespaces,
			first_seen, last_seen,
			critical, high, medium, low, total_vulns,
			scan_status, scanned_at, image_labels
		FROM image_catalog
		WHERE 1=1`
	args := []any{}
	idx := 1

	if cluster != "" {
		query += ` AND cluster_id = $` + strconv.Itoa(idx)
		args = append(args, cluster)
		idx++
	}
	if scanStatus != "" {
		query += ` AND scan_status = $` + strconv.Itoa(idx)
		args = append(args, scanStatus)
		idx++
	}
	if source == "chainguard" {
		query += ` AND image_labels->>'org.opencontainers.image.vendor' = $` + strconv.Itoa(idx)
		args = append(args, "Chainguard")
	}
	query += ` ORDER BY total_vulns DESC, pod_count DESC`

	rows, err := a.store.Pool().Query(r.Context(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := []ImageEntry{}
	for rows.Next() {
		var e ImageEntry
		rows.Scan( //nolint:errcheck
			&e.Image, &e.ImageDigest, &e.ClusterID,
			&e.NamespaceCount, &e.PodCount, &e.Namespaces,
			&e.FirstSeen, &e.LastSeen,
			&e.Critical, &e.High, &e.Medium, &e.Low, &e.TotalVulns,
			&e.ScanStatus, &e.ScannedAt, &e.ImageLabels,
		)
		e.IsChainguard = strings.Contains(e.ImageLabels, `"Chainguard"`)
		results = append(results, e)
	}
	return results, nil
}

func (a *API) inventory(w http.ResponseWriter, r *http.Request) {
	query := `SELECT cluster_id, namespace, pod_name, image, phase FROM pod_inventory`
	args := []any{}

	if cluster := r.URL.Query().Get("cluster"); cluster != "" {
		query += ` WHERE cluster_id = $1`
		args = append(args, cluster)
	}

	rows, err := a.store.Pool().Query(r.Context(), query, args...)
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

	results := []Pod{}
	for rows.Next() {
		var p Pod
		rows.Scan(&p.ClusterID, &p.Namespace, &p.PodName, &p.Image, &p.Phase) //nolint:errcheck
		results = append(results, p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results) //nolint:errcheck
}
