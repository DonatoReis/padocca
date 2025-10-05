// Padocca Web Crawler - High-performance web spider with JS rendering
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/sync/semaphore"
)

// CrawlerConfig holds crawler configuration
type CrawlerConfig struct {
	MaxDepth      int
	MaxWorkers    int64
	Timeout       time.Duration
	UserAgent     string
	RenderJS      bool
	ExtractEmails bool
	ExtractPhones bool
	ExtractForms  bool
	ExtractAPIs   bool
}

// CrawlResult contains the crawl results
type CrawlResult struct {
	URL          string        `json:"url"`
	StatusCode   int           `json:"status_code"`
	Title        string        `json:"title"`
	Emails       []string      `json:"emails,omitempty"`
	Phones       []string      `json:"phones,omitempty"`
	Forms        []FormInfo    `json:"forms,omitempty"`
	APIs         []string      `json:"apis,omitempty"`
	Links        []string      `json:"links,omitempty"`
	Scripts      []string      `json:"scripts,omitempty"`
	Depth        int           `json:"depth"`
	ResponseTime time.Duration `json:"response_time"`
}

// FormInfo contains form information
type FormInfo struct {
	Action string            `json:"action"`
	Method string            `json:"method"`
	Fields map[string]string `json:"fields"`
}

// Crawler struct
type Crawler struct {
	config     *CrawlerConfig
	visited    map[string]bool
	results    []CrawlResult
	mutex      sync.RWMutex
	sem        *semaphore.Weighted
	baseURL    *url.URL
	httpClient *http.Client
}

// Regular expressions for extraction
var (
	emailRegex = regexp.MustCompile(`[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}`)
	phoneRegex = regexp.MustCompile(`[\+]?[(]?[0-9]{1,3}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,9}`)
	apiRegex   = regexp.MustCompile(`(?i)(api|graphql|rest|v[0-9]+|endpoint)`)
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "crawler",
		Short: "Padocca Web Crawler - Advanced web spider",
		Long:  `High-performance web crawler with JavaScript rendering capabilities`,
		Run:   runCrawler,
	}

	// Define flags
	rootCmd.Flags().StringP("url", "u", "", "Target URL to crawl (required)")
	rootCmd.Flags().IntP("depth", "d", 3, "Maximum crawl depth")
	rootCmd.Flags().IntP("workers", "w", 10, "Number of concurrent workers")
	rootCmd.Flags().IntP("timeout", "t", 30, "Request timeout in seconds")
	rootCmd.Flags().BoolP("js", "j", false, "Enable JavaScript rendering")
	rootCmd.Flags().BoolP("extract-all", "e", false, "Extract all information")
	rootCmd.Flags().StringP("output", "o", "", "Output file (JSON format)")

	rootCmd.MarkFlagRequired("url")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runCrawler(cmd *cobra.Command, args []string) {
	// Parse flags
	targetURL, _ := cmd.Flags().GetString("url")
	maxDepth, _ := cmd.Flags().GetInt("depth")
	workers, _ := cmd.Flags().GetInt("workers")
	timeout, _ := cmd.Flags().GetInt("timeout")
	renderJS, _ := cmd.Flags().GetBool("js")
	extractAll, _ := cmd.Flags().GetBool("extract-all")
	outputFile, _ := cmd.Flags().GetString("output")

	// Validate URL
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	baseURL, err := url.Parse(targetURL)
	if err != nil {
		log.Fatal(color.RedString("Invalid URL: %v", err))
	}

	// Print banner
	printBanner()

	// Create crawler config
	config := &CrawlerConfig{
		MaxDepth:      maxDepth,
		MaxWorkers:    int64(workers),
		Timeout:       time.Duration(timeout) * time.Second,
		UserAgent:     "Padocca/2.0 (Web Crawler)",
		RenderJS:      renderJS,
		ExtractEmails: extractAll,
		ExtractPhones: extractAll,
		ExtractForms:  extractAll,
		ExtractAPIs:   extractAll,
	}

	// Initialize crawler
	// HTTP client with sane defaults and optional insecure TLS
	transport := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
	}

	crawler := &Crawler{
		config:     config,
		visited:    make(map[string]bool),
		results:    []CrawlResult{},
		sem:        semaphore.NewWeighted(config.MaxWorkers),
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: config.Timeout, Transport: transport},
	}

	// Start crawling
	color.Cyan("🕷️  Starting crawl of %s", targetURL)
	color.Yellow("📊 Max depth: %d | Workers: %d | JS: %v\n", maxDepth, workers, renderJS)

	startTime := time.Now()
	crawler.Crawl(targetURL, 0)

	elapsed := time.Since(startTime)

	// Display results
	crawler.DisplayResults()

	color.Green("\n✅ Crawl completed in %v", elapsed)
	color.Cyan("📈 Pages crawled: %d", len(crawler.results))

	// Save results if output file specified
	if outputFile != "" {
		if err := crawler.SaveResults(outputFile); err != nil {
			color.Red("Error saving results: %v", err)
		} else {
			color.Green("Results saved to %s", outputFile)
		}
	}
}

func (c *Crawler) Crawl(targetURL string, depth int) {
	// Check depth limit
	if depth > c.config.MaxDepth {
		return
	}

	// Check if already visited
	c.mutex.Lock()
	if c.visited[targetURL] {
		c.mutex.Unlock()
		return
	}
	c.visited[targetURL] = true
	c.mutex.Unlock()

	// Acquire semaphore
	ctx := context.Background()
	c.sem.Acquire(ctx, 1)
	defer c.sem.Release(1)

	// Fetch page
	result := CrawlResult{
		URL:   targetURL,
		Depth: depth,
	}

	startTime := time.Now()

	if c.config.RenderJS {
		// Use headless browser for JS rendering
		c.crawlWithJS(targetURL, &result)
	} else {
		// Standard HTTP request
		c.crawlStandard(targetURL, &result)
	}

	result.ResponseTime = time.Since(startTime)

	// Store result
	c.mutex.Lock()
	c.results = append(c.results, result)
	c.mutex.Unlock()

	// Crawl discovered links
	var wg sync.WaitGroup
	for _, link := range result.Links {
		if c.shouldCrawl(link) {
			wg.Add(1)
			go func(l string) {
				defer wg.Done()
				c.Crawl(l, depth+1)
			}(link)
		}
	}
	wg.Wait()
}

func (c *Crawler) crawlStandard(targetURL string, result *CrawlResult) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		fallbackURL := strings.Replace(targetURL, "https://", "http://", 1)
		if fallbackURL != targetURL {
			req, err = http.NewRequest("GET", fallbackURL, nil)
			if err == nil {
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
				resp, err = c.httpClient.Do(req)
			}
		}
		if err != nil {
			return
		}
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return
	}

	// Extract title
	result.Title = doc.Find("title").Text()

	// Extract links
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			if absoluteURL := c.resolveURL(href); absoluteURL != "" {
				result.Links = append(result.Links, absoluteURL)
			}
		}
	})

	// Extract emails efficiently without duplicates
	emailMap := make(map[string]bool)

	// Extract from full HTML once
	html, _ := doc.Html()
	emails := c.extractEmails(html)
	for _, email := range emails {
		emailMap[strings.ToLower(email)] = true
	}

	// Convert map to slice for unique emails
	for email := range emailMap {
		result.Emails = append(result.Emails, email)
	}

	// Extract phones if enabled
	if c.config.ExtractPhones {
		html, _ := doc.Html()
		result.Phones = c.extractPhones(html)
	}

	// Extract forms if enabled
	if c.config.ExtractForms {
		result.Forms = c.extractForms(doc)
	}

	// Extract API endpoints if enabled
	if c.config.ExtractAPIs {
		result.APIs = c.extractAPIs(doc)
	}
}

func (c *Crawler) crawlWithJS(targetURL string, result *CrawlResult) {
	// Create context
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	// Set timeout
	ctx, cancel = context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	var html string
	err := chromedp.Run(ctx,
		chromedp.Navigate(targetURL),
		chromedp.WaitReady("body"),
		chromedp.OuterHTML("html", &html),
	)

	if err != nil {
		return
	}

	// Parse HTML
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return
	}

	// Extract data (similar to crawlStandard)
	result.Title = doc.Find("title").Text()
	result.StatusCode = 200 // Assume success for JS rendering

	// Extract other elements...
	// (Implementation similar to crawlStandard)
}

func (c *Crawler) shouldCrawl(link string) bool {
	parsedURL, err := url.Parse(link)
	if err != nil {
		return false
	}

	// Only crawl same domain
	return parsedURL.Host == c.baseURL.Host
}

func (c *Crawler) resolveURL(href string) string {
	parsedURL, err := url.Parse(href)
	if err != nil {
		return ""
	}

	resolvedURL := c.baseURL.ResolveReference(parsedURL)
	return resolvedURL.String()
}

func (c *Crawler) extractEmails(html string) []string {
	matches := emailRegex.FindAllString(html, -1)
	unique := make(map[string]bool)
	var result []string

	for _, match := range matches {
		if !unique[match] {
			unique[match] = true
			result = append(result, match)
		}
	}
	return result
}

func (c *Crawler) extractPhones(html string) []string {
	matches := phoneRegex.FindAllString(html, -1)
	unique := make(map[string]bool)
	var result []string

	for _, match := range matches {
		if !unique[match] {
			unique[match] = true
			result = append(result, match)
		}
	}
	return result
}

func (c *Crawler) extractForms(doc *goquery.Document) []FormInfo {
	var forms []FormInfo

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		form := FormInfo{
			Fields: make(map[string]string),
		}

		if action, exists := s.Attr("action"); exists {
			form.Action = action
		}

		if method, exists := s.Attr("method"); exists {
			form.Method = strings.ToUpper(method)
		} else {
			form.Method = "GET"
		}

		// Extract form fields
		s.Find("input, textarea, select").Each(func(j int, field *goquery.Selection) {
			name, _ := field.Attr("name")
			fieldType, _ := field.Attr("type")
			if name != "" {
				form.Fields[name] = fieldType
			}
		})

		forms = append(forms, form)
	})

	return forms
}

func (c *Crawler) extractAPIs(doc *goquery.Document) []string {
	var apis []string
	unique := make(map[string]bool)

	// Check scripts for API endpoints
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		text := s.Text()
		if apiRegex.MatchString(text) {
			// Extract potential API URLs
			// (Simplified - in production would be more sophisticated)
			if !unique[text] {
				unique[text] = true
				apis = append(apis, "Potential API found in script")
			}
		}
	})

	return apis
}

func (c *Crawler) DisplayResults() {
	fmt.Println()
	color.Yellow("═══════════════════════════════════════════════════════")
	color.Cyan("                    CRAWL RESULTS                      ")
	color.Yellow("═══════════════════════════════════════════════════════")

	emailCount := 0
	phoneCount := 0
	formCount := 0

	for _, result := range c.results {
		emailCount += len(result.Emails)
		phoneCount += len(result.Phones)
		formCount += len(result.Forms)

		if len(result.Emails) > 0 || len(result.Phones) > 0 || len(result.Forms) > 0 {
			fmt.Printf("\n%s %s\n", color.GreenString("[+]"), result.URL)

			if len(result.Emails) > 0 {
				fmt.Printf("    %s Emails: %v\n", color.YellowString("📧"), result.Emails)
			}

			if len(result.Phones) > 0 {
				fmt.Printf("    %s Phones: %v\n", color.CyanString("📱"), result.Phones)
			}

			if len(result.Forms) > 0 {
				fmt.Printf("    %s Forms: %d found\n", color.MagentaString("📝"), len(result.Forms))
			}
		}
	}

	fmt.Println()
	color.Green("📊 Statistics:")
	fmt.Printf("   • Pages crawled: %d\n", len(c.results))
	fmt.Printf("   • Emails found: %d\n", emailCount)
	fmt.Printf("   • Phones found: %d\n", phoneCount)
	fmt.Printf("   • Forms found: %d\n", formCount)
}

func (c *Crawler) SaveResults(filename string) error {
	data, err := json.MarshalIndent(c.results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func printBanner() {
	banner := `
    ╔════════════════════════════════════╗
    ║   🕷️  PADOCCA WEB CRAWLER 🕷️      ║
    ║     Fast • Smart • Stealthy        ║
    ╚════════════════════════════════════╝
    `
	color.Cyan(banner)
}
