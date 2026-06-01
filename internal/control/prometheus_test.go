package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPrometheusClientQueryScalar(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" || r.URL.Query().Get("query") == "" {
			t.Fatalf("bad prometheus query request: %s", r.URL.String())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]any{
				"resultType": "vector",
				"result": []any{map[string]any{
					"value": []any{float64(1), "42"},
				}},
			},
		})
	}))
	defer server.Close()

	metrics, err := NewControlMetrics()
	if err != nil {
		t.Fatal(err)
	}
	value, status := NewPrometheusClient(server.URL, metrics).QueryScalar(context.Background(), "sum(up)")
	if !status.Configured || !status.Healthy || value != 42 {
		t.Fatalf("value=%v status=%#v", value, status)
	}
}
