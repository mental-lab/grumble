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
	return mux
}

// health satisfies the Grafana JSON datasource /  check
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
