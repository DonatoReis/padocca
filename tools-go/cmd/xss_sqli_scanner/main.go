package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type Endpoint struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Body    string            `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type EndpointSummary struct {
	Method string `json:"method"`
	URL    string `json:"url"`
}

type Finding struct {
	Endpoint    EndpointSummary `json:"endpoint"`
	Payload     string          `json:"payload"`
	Type        string          `json:"type"`
	Description string          `json:"description"`
	Evidence    string          `json:"evidence"`
}

type ScanResult struct {
	Target     string    `json:"target"`
	Findings   []Finding `json:"findings"`
	StartedAt  string    `json:"started_at"`
	FinishedAt string    `json:"finished_at"`
}

var (
	xssPayloads = []string{
		`"'><script>document.body.setAttribute('data-padocca','xss')</script>`,
		`'><img src=x onerror=alert('padocca')>`,
		`"/><svg/onload=alert('padocca')>`,
	}

	sqlPayloads = []string{
		"' OR '1'='1",
		"\" OR \"1\"=\"1",
		"') OR ('1'='1",
		"' UNION SELECT null,null--",
	}

	sqlErrorSignatures = []string{
		"sql syntax",
		"mysql_fetch",
		"ora-",
		"odbc driver",
		"invalid sql",
		"sqlstate",
		"sqlite",
		"warning: mysql",
		"division by zero",
	}
)

func main() {
	timeout := flag.Int("timeout", 10, "HTTP timeout in seconds")
	defaultMethod := flag.String("method", "GET", "Default HTTP method for the base target")
	defaultBody := flag.String("data", "", "Default request body template (use {payload} or {payload_url})")
	endpointFile := flag.String("endpoint-file", "", "JSON file with custom endpoints")

	var endpointFlags stringList
	var headerFlags stringList
	var cookieFlags stringList

	flag.Var(&endpointFlags, "endpoint", "Custom endpoint in the format METHOD::URL[::BODY]")
	flag.Var(&headerFlags, "header", "Custom header 'Name: Value'")
	flag.Var(&cookieFlags, "cookie", "Cookie 'name=value'")

	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: xss_sqli_scanner [options] <url>")
		flag.PrintDefaults()
		os.Exit(2)
	}

	rawURL := flag.Arg(0)
	baseURL, err := url.Parse(rawURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid URL: %v\n", err)
		os.Exit(2)
	}

	if baseURL.Scheme == "" {
		baseURL.Scheme = "https"
	}

	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Timeout: time.Duration(*timeout) * time.Second, Transport: transport}

	globalHeaders := parseHeaders(headerFlags)
	cookieHeader := strings.Join(cookieFlags, "; ")

	endpoints, err := loadEndpoints(baseURL, endpointFlags, *endpointFile, *defaultMethod, *defaultBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load endpoints: %v\n", err)
		os.Exit(2)
	}

	result := ScanResult{Target: baseURL.String(), StartedAt: time.Now().Format(time.RFC3339)}

	for _, ep := range endpoints {
		for _, payload := range xssPayloads {
			if finding := evaluatePayload(client, baseURL, ep, payload, globalHeaders, cookieHeader, true, false); finding != nil {
				result.Findings = append(result.Findings, *finding)
			}
		}

		for _, payload := range sqlPayloads {
			if finding := evaluatePayload(client, baseURL, ep, payload, globalHeaders, cookieHeader, false, true); finding != nil {
				result.Findings = append(result.Findings, *finding)
			}
		}
	}

	result.FinishedAt = time.Now().Format(time.RFC3339)

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode result: %v\n", err)
		os.Exit(1)
	}
}

func evaluatePayload(client *http.Client, base *url.URL, endpoint Endpoint, payload string, globalHeaders map[string]string, cookieHeader string, checkXSS bool, checkSQL bool) *Finding {
	method, finalURL, body := prepareRequest(base, endpoint, payload)

	headers := cloneHeaders(globalHeaders)
	for k, v := range endpoint.Headers {
		headers[k] = v
	}

	responseBody, err := doRequest(client, method, finalURL, body, headers, cookieHeader)
	if err != nil {
		return nil
	}

	summary := EndpointSummary{Method: method, URL: finalURL}

	if checkXSS {
		if finding := detectReflection(responseBody, payload, summary); finding != nil {
			return finding
		}
	}

	if checkSQL {
		if finding := detectSQLError(responseBody, payload, summary); finding != nil {
			return finding
		}
	}

	return nil
}

func prepareRequest(base *url.URL, ep Endpoint, payload string) (string, string, string) {
	method := strings.ToUpper(strings.TrimSpace(ep.Method))
	if method == "" {
		method = "GET"
	}

	rawURL := strings.TrimSpace(ep.URL)
	finalURL := resolveURL(base, applyTemplate(rawURL, payload))

	body := applyTemplate(ep.Body, payload)

	if method == "GET" {
		if !strings.Contains(strings.ToLower(finalURL), strings.ToLower(payload)) && !strings.Contains(strings.ToLower(body), strings.ToLower(payload)) {
			u, err := url.Parse(finalURL)
			if err == nil {
				q := u.Query()
				q.Set("padocca", payload)
				u.RawQuery = q.Encode()
				finalURL = u.String()
			}
		}
		body = ""
	} else {
		if body == "" {
			body = applyTemplate("padocca={payload}", payload)
		}
	}

	return method, finalURL, body
}

func resolveURL(base *url.URL, raw string) string {
	if raw == "" {
		return base.String()
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return base.String()
	}

	if parsed.Scheme == "" {
		return base.ResolveReference(parsed).String()
	}
	return parsed.String()
}

func applyTemplate(template, payload string) string {
	if template == "" {
		return ""
	}
	replacer := strings.NewReplacer(
		"{payload}", payload,
		"{payload_url}", url.QueryEscape(payload),
		"{payload_enc}", url.QueryEscape(payload),
	)
	return replacer.Replace(template)
}

func detectReflection(body, payload string, endpoint EndpointSummary) *Finding {
	if body == "" {
		return nil
	}

	if strings.Contains(body, payload) {
		return &Finding{
			Endpoint:    endpoint,
			Payload:     payload,
			Type:        "xss_reflection",
			Description: "Payload appears unencoded in the response body",
			Evidence:    snippet(body, payload, 120),
		}
	}

	encoded := url.QueryEscape(payload)
	if strings.Contains(body, encoded) {
		return &Finding{
			Endpoint:    endpoint,
			Payload:     payload,
			Type:        "xss_reflection",
			Description: "Payload reflected with basic encoding (potential DOM sink)",
			Evidence:    snippet(body, encoded, 120),
		}
	}

	return nil
}

func detectSQLError(body, payload string, endpoint EndpointSummary) *Finding {
	if body == "" {
		return nil
	}

	lower := strings.ToLower(body)
	for _, sig := range sqlErrorSignatures {
		signature := strings.ToLower(sig)
		if strings.Contains(lower, signature) {
			return &Finding{
				Endpoint:    endpoint,
				Payload:     payload,
				Type:        "sql_error",
				Description: "Potential SQL error message discovered",
				Evidence:    snippet(body, sig, 160),
			}
		}
	}
	return nil
}

func doRequest(client *http.Client, method, target, body string, headers map[string]string, cookieHeader string) (string, error) {
	var reader io.Reader
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		if body != "" {
			reader = strings.NewReader(body)
		}
	}

	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		return "", err
	}

	if reader != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if cookieHeader != "" {
		req.Header.Add("Cookie", cookieHeader)
	}

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
	}

	resp, err := client.Do(req)
	if err != nil {
		if strings.HasPrefix(target, "https://") {
			fallback := strings.Replace(target, "https://", "http://", 1)
			req.URL, err = url.Parse(fallback)
			if err == nil {
				if reader != nil {
					req.Body = io.NopCloser(strings.NewReader(body))
				}
				resp, err = client.Do(req)
			}
		}
		if err != nil {
			return "", err
		}
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 524288))
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func parseHeaders(values []string) map[string]string {
	headers := make(map[string]string)
	for _, h := range values {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key != "" {
			headers[key] = value
		}
	}
	return headers
}

func cloneHeaders(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func loadEndpoints(base *url.URL, endpointFlags stringList, endpointFile, defaultMethod, defaultBody string) ([]Endpoint, error) {
	var endpoints []Endpoint

	for _, flagValue := range endpointFlags {
		ep, err := parseEndpointFlag(flagValue)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, ep)
	}

	if endpointFile != "" {
		fileEndpoints, err := parseEndpointFile(endpointFile)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, fileEndpoints...)
	}

	if len(endpoints) == 0 {
		endpoints = append(endpoints, Endpoint{Method: defaultMethod, URL: base.String(), Body: defaultBody})
	}

	for i := range endpoints {
		endpoints[i].Method = strings.ToUpper(strings.TrimSpace(endpoints[i].Method))
		if endpoints[i].Method == "" {
			endpoints[i].Method = strings.ToUpper(strings.TrimSpace(defaultMethod))
			if endpoints[i].Method == "" {
				endpoints[i].Method = "GET"
			}
		}

		if endpoints[i].URL == "" {
			endpoints[i].URL = base.String()
		} else {
			if !strings.HasPrefix(endpoints[i].URL, "http") {
				endpoints[i].URL = (base.ResolveReference(&url.URL{Path: endpoints[i].URL})).String()
			}
		}
	}

	return endpoints, nil
}

func parseEndpointFlag(value string) (Endpoint, error) {
	parts := strings.SplitN(value, "::", 3)
	if len(parts) < 2 {
		return Endpoint{}, errors.New("endpoint flag format METHOD::URL[::BODY]")
	}

	ep := Endpoint{
		Method: strings.TrimSpace(parts[0]),
		URL:    strings.TrimSpace(parts[1]),
	}
	if len(parts) == 3 {
		ep.Body = parts[2]
	}
	return ep, nil
}

func parseEndpointFile(path string) ([]Endpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var endpoints []Endpoint
	if err := json.Unmarshal(data, &endpoints); err != nil {
		return nil, err
	}
	return endpoints, nil
}

func snippet(body, needle string, radius int) string {
	lowerBody := strings.ToLower(body)
	lowerNeedle := strings.ToLower(needle)
	idx := strings.Index(lowerBody, lowerNeedle)
	if idx == -1 {
		return ""
	}
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + radius
	if end > len(body) {
		end = len(body)
	}
	snippet := body[start:end]
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	snippet = strings.ReplaceAll(snippet, "\r", " ")
	return snippet
}
