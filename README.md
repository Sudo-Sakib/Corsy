# CORSy - CORS Misconfiguration Scanner

CORSy is a tool to scan websites for Cross-Origin Resource Sharing (CORS) misconfigurations. It helps identify potential security risks, such as wildcard (`*`) or insecure origins, by checking the website's CORS headers.

## Pre-requisites

Before you begin, you need to have **Go** installed. If you're using **Kali Linux**, you can install Go with the following commands:

```bash
sudo apt-get update
sudo apt install golang -y
```

To verify if Go is installed correctly, run:
```bash
  go version
``` 
### Step to Install

```bash
  git clone <url>
  cd dir
  go build -o corsy corsy.go
  sudo mv corsy /usr/local/bin
```
### Usage
#### 1. To scan a single URL:
```bash
  corsy -u https://example.com
``` 
#### 2. To scan multiple URLs from a file:

```bash
  corsy -i urls.txt
```
#### 3. To save results to a file:
```bash
  corsy -u https://example.com -o results.json
```
