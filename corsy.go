package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

type Result struct {
	URL               string            `json:"url"`
	CORSHeaders       map[string]string `json:"cors_headers"`
	Misconfigurations []string          `json:"misconfigurations"`
}

var (
	urlFlag    = flag.String("u", "", "Single URL to scan for CORS issues")
	inputFile  = flag.String("i", "", "Input file containing URLs to scan")
	outputFile = flag.String("o", "", "Output file to save results")
	timeout    = flag.Int("t", 10, "Timeout for HTTP requests in seconds")
)

const (
	Red   = "\033[31m" // Red color for vulnerable URLs
	Green = "\033[32m" // Green color for non-vulnerable URLs
	Reset = "\033[0m"  // Reset color to default
)

// Get URLs from the command-line flag or input file
func getURLs() []string {
	var urls []string

	if *urlFlag != "" {
		urls = append(urls, *urlFlag)
	}

	if *inputFile != "" {
		file, err := os.Open(*inputFile)
		if err != nil {
			fmt.Printf("Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			urls = append(urls, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading file: %v\n", err)
			os.Exit(1)
		}
	}

	if len(urls) == 0 {
		fmt.Println("No URLs provided. Use -u or -i flag.")
		os.Exit(1)
	}

	return urls
}

// Scan a single URL for CORS misconfigurations
func scanURL(url string) Result {
	client := &http.Client{Timeout: time.Duration(*timeout) * time.Second}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating request for URL %s: %v\n", url, err)
		return Result{URL: url, Misconfigurations: []string{"Request creation failed"}}
	}

	req.Header.Set("Origin", "https://evil.com")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error making request to URL %s: %v\n", url, err)
		return Result{URL: url, Misconfigurations: []string{"Request failed"}}
	}
	defer resp.Body.Close()

	corsHeaders := map[string]string{}
	for key, values := range resp.Header {
		if strings.Contains(strings.ToLower(key), "access-control") {
			corsHeaders[key] = strings.Join(values, ", ")
		}
	}

	misconfigurations := []string{}
	if value, ok := corsHeaders["Access-Control-Allow-Origin"]; ok {
		if value == "*" || value == "https://evil.com" {
			misconfigurations = append(misconfigurations, "Wildcard or insecure Origin allowed")
		}
	}

	return Result{
		URL:               url,
		CORSHeaders:       corsHeaders,
		Misconfigurations: misconfigurations,
	}
}

// Write the scan results to a JSON file
func writeResultsToFile(results []Result, filename string) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling results to JSON: %v\n", err)
		return
	}

	err = ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
	}
}

// Print the scan results to the console with color coding
func printResults(results []Result) {
	for _, result := range results {
		if len(result.Misconfigurations) > 0 {
			// Vulnerable: Print in red
			fmt.Printf("%s[!] VULNERABLE: %s%s\n", Red, result.URL, Reset)
			fmt.Printf("%sCORS Headers: %v%s\n", Red, result.CORSHeaders, Reset)
			fmt.Printf("%sMisconfigurations: %v%s\n", Red, result.Misconfigurations, Reset)
		} else {
			// Not vulnerable: Print in green
			fmt.Printf("%s[+] SECURE: %s%s\n", Green, result.URL, Reset)
			fmt.Printf("%sCORS Headers: %v%s\n", Green, result.CORSHeaders, Reset)
		}
		fmt.Println("-------------------------------------------------")
	}
}

// Main function
func main() {
	flag.Parse()

	if *urlFlag == "" && *inputFile == "" {
		fmt.Println("Error: No URLs provided. Use -u for a single URL or -i for an input file.")
		flag.Usage()
		os.Exit(1)
	}

	urls := getURLs()
	results := []Result{}

	for _, url := range urls {
		fmt.Printf("Scanning URL: %s\n", url)
		result := scanURL(url)
		results = append(results, result)
	}

	if *outputFile != "" {
		writeResultsToFile(results, *outputFile)
		fmt.Printf("Results saved to file: %s\n", *outputFile)
	} else {
		printResults(results)
	}
}
