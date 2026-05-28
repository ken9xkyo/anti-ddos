package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type PrometheusClient struct {
	baseURL string
	metrics *ControlMetrics
	client  *http.Client
}

func NewPrometheusClient(baseURL string, metrics *ControlMetrics) *PrometheusClient {
	return &PrometheusClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		metrics: metrics,
		client:  &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *PrometheusClient) Configured() bool {
	return c != nil && c.baseURL != ""
}

func (c *PrometheusClient) QueryScalar(ctx context.Context, promQL string) (float64, PrometheusStatus) {
	if c == nil || c.baseURL == "" {
		return 0, PrometheusStatus{Configured: false, Healthy: false, Error: "prometheus is not configured"}
	}
	endpoint := c.baseURL + "/api/v1/query?query=" + url.QueryEscape(promQL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		c.inc("error")
		return 0, PrometheusStatus{Configured: true, Healthy: false, Error: err.Error()}
	}
	resp, err := c.client.Do(req)
	if err != nil {
		c.inc("error")
		return 0, PrometheusStatus{Configured: true, Healthy: false, Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c.inc("error")
		return 0, PrometheusStatus{Configured: true, Healthy: false, Error: fmt.Sprintf("prometheus status %d", resp.StatusCode)}
	}
	var out prometheusQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		c.inc("error")
		return 0, PrometheusStatus{Configured: true, Healthy: false, Error: err.Error()}
	}
	if out.Status != "success" {
		c.inc("error")
		if out.Error != "" {
			return 0, PrometheusStatus{Configured: true, Healthy: false, Error: out.Error}
		}
		return 0, PrometheusStatus{Configured: true, Healthy: false, Error: "prometheus query failed"}
	}
	value, err := out.scalar()
	if err != nil {
		c.inc("empty")
		return 0, PrometheusStatus{Configured: true, Healthy: true}
	}
	c.inc("ok")
	return value, PrometheusStatus{Configured: true, Healthy: true}
}

func (c *PrometheusClient) inc(result string) {
	if c.metrics != nil {
		c.metrics.IncPrometheusQuery(result)
	}
}

type prometheusQueryResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	Data   struct {
		ResultType string             `json:"resultType"`
		Result     []prometheusVector `json:"result"`
	} `json:"data"`
}

type prometheusVector struct {
	Value []any `json:"value"`
}

func (r prometheusQueryResponse) scalar() (float64, error) {
	if len(r.Data.Result) == 0 || len(r.Data.Result[0].Value) < 2 {
		return 0, errors.New("empty prometheus vector")
	}
	text, ok := r.Data.Result[0].Value[1].(string)
	if !ok {
		return 0, errors.New("prometheus value is not a string")
	}
	return strconv.ParseFloat(text, 64)
}
