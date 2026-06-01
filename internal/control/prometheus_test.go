package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestPrometheusClientQueryScalarErrors(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		baseURL    string
		wantConfig bool
		wantHealth bool
		wantError  string
	}{
		{
			name:       "unconfigured",
			wantError:  "not configured",
			wantConfig: false,
			wantHealth: false,
		},
		{
			name: "non-200",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "unavailable", http.StatusInternalServerError)
			},
			wantConfig: true,
			wantHealth: false,
			wantError:  "status 500",
		},
		{
			name: "malformed json",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("not-json"))
			},
			wantConfig: true,
			wantHealth: false,
			wantError:  "invalid",
		},
		{
			name: "prometheus error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "error", "error": "bad query"})
			},
			wantConfig: true,
			wantHealth: false,
			wantError:  "bad query",
		},
		{
			name: "empty result is healthy zero",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status": "success",
					"data":   map[string]any{"resultType": "vector", "result": []any{}},
				})
			},
			wantConfig: true,
			wantHealth: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseURL := tt.baseURL
			if tt.handler != nil {
				server := httptest.NewServer(tt.handler)
				defer server.Close()
				baseURL = server.URL
			}

			value, status := NewPrometheusClient(baseURL, nil).QueryScalar(context.Background(), "sum(up)")
			if value != 0 {
				t.Fatalf("value=%v want 0", value)
			}
			if status.Configured != tt.wantConfig || status.Healthy != tt.wantHealth {
				t.Fatalf("status=%#v want configured=%v healthy=%v", status, tt.wantConfig, tt.wantHealth)
			}
			if tt.wantError != "" && !strings.Contains(status.Error, tt.wantError) {
				t.Fatalf("error=%q want containing %q", status.Error, tt.wantError)
			}
		})
	}
}
