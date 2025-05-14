# S3 Bucket and JavaScript Endpoint Extractor

A Python-based tool to extract S3 buckets and endpoints from JavaScript files or web URLs, featuring advanced JavaScript parsing with Esprima, endpoint extraction with LinkFinder, and S3 bucket discovery via GitHub API. The tool includes a user-friendly tkinter GUI and supports ethical crawling with robots.txt compliance.

## Features

### Input Processing
* Analyzes local JavaScript/HTML files or web URLs.
* Crawls websites with configurable depth and page limits.
* Parses sitemaps to discover additional URLs.

### Endpoint Extraction
* Uses Esprima (Node.js) for advanced JavaScript AST parsing.
* Integrates LinkFinder for endpoint detection in JS files.
* Falls back to regex-based extraction with `jsbeautifier`.

### S3 Bucket Enumeration
* Extracts S3 bucket URLs using regex.
* Generates potential bucket names from input.
* Searches GitHub for S3 buckets using the GitHub API (requires PAT).
* Tests buckets for public access (listable/readable).

### GUI
* Configurable settings for LinkFinder, Esprima, GitHub search, and crawling.
* Displays extracted endpoints, JS files, and S3 buckets.
* Supports exporting results to text, JSON, or HTML reports.

### Ethical Features
* Respects `robots.txt` for web crawling.
* Caches GitHub API results to minimize rate limit issues.

### Logging
* Detailed logs (`extractor.log`) for debugging and tracking.

## Prerequisites

* **Operating System:** Windows (tested on Windows 10/11).
* **Python:** Version 3.13 or later.
* **Node.js:** Version 20.17.0 (LTS) or compatible for Esprima parsing.

## Installation

1.  **Clone or Download the Repository:**
    ```bash
    git clone [https://github.com/TheOSuite/oJSS3.git](https://github.com/TheOSuite/oJSS3.git)
    cd oJSS3
    ```
    Alternatively, download `oJSS3.py` and place it in a directory (e.g., `C:\Users\user\Documents\oHAR\oHAR-FINAL`).

2.  **Install Python Dependencies:**
    ```bash
    pip install requests beautifulsoup4 jsbeautifier lxml
    ```
    `lxml` is required for XML sitemap parsing. If installation fails (e.g., missing C++ compiler), install a precompiled wheel:
    ```bash
    pip install lxml --only-binary :all:
    ```
    Or download from [https://www.lfd.uci.edu/~gohlke/pythonlibs/#lxml](https://www.lfd.uci.edu/~gohlke/pythonlibs/#lxml) (e.g., `lxml-5.3.0-cp313-cp313-win_amd64.whl`):
    ```cmd
    pip install path\to\lxml-5.3.0-cp313-cp313-win_amd64.whl
    ```
    Optional: Install `js2py` for experimental JS execution:
    ```bash
    pip install js2py
    ```

3.  **Install Node.js and Esprima:**
    Download Node.js LTS (20.17.0) from [https://nodejs.org/dist/v20.17.0/node-v20.17.0-x64.msi](https://nodejs.org/dist/v20.17.0/node-v20.17.0-x64.msi).

    Install with **Add to PATH** enabled.

    Verify:
    ```cmd
    node --version
    npm --version
    ```
    Expected: `v20.17.0`, `10.8.3` (or similar).

    Install Esprima:
    ```cmd
    cd C:\LinkFinder
    npm install esprima
    ```
    Verify:
    ```cmd
    dir C:\LinkFinder\node_modules\esprima
    npm list esprima
    ```
    Expected: `esprima@4.0.1` or similar.

    Ensure `parse_js.js` is at `C:\LinkFinder\parse_js.js`. Example content:
    ```javascript
    const fs = require('fs');
    const esprima = require('esprima');

    if (process.argv.length < 3) {
        console.error('Usage: node parse_js.js <input_file>');
        process.exit(1);
    }

    const inputFile = process.argv[2];
    const s3Pattern = /(?:https?:\/\/)?(?:[a-z0-9\-]+\.)?s3[.-](?:[a-z0-9\-]+\.)?amazonaws\.com\/([a-z0-9\-]+)|(?:https?:\/\/)?([a-z0-9\-]+)\.s3[.-](?:[a-z0-9\-]+\.)?amazonaws\.com|(?:https?:\/\/)?s3\.amazonaws\.com\/([a-z0-9\-]+)|(?:https?:\/\/)?([a-z0-9\-]+)\.s3-website[.-][a-z0-9\-]+\.amazonaws\.com/gi;
    const urlPattern = /(?:https?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+/gi;

    function extractEndpoints(node, endpoints = new Set()) {
        if (!node) return endpoints;
        if (node.type === 'Literal' && typeof node.value === 'string') {
            if (urlPattern.test(node.value) || s3Pattern.test(node.value)) {
                endpoints.add(node.value);
            }
        } else if (node.type === 'TemplateLiteral') {
            node.quasis.forEach(quasi => {
                if (quasi.value && quasi.value.raw && (urlPattern.test(quasi.value.raw) || s3Pattern.test(quasi.value.raw))) {
                    endpoints.add(quasi.value.raw);
                }
            });
        } else if (node.type === 'ObjectExpression') {
            node.properties.forEach(prop => {
                if (prop.value && prop.value.type === 'Literal' && typeof prop.value.value === 'string') {
                    if (urlPattern.test(prop.value.value) || s3Pattern.test(prop.value.value)) {
                        endpoints.add(prop.value.value);
                    }
                }
            });
        }
        for (let key in node) {
            if (node[key] && typeof node[key] === 'object') {
                extractEndpoints(node[key], endpoints);
            }
        }
        return endpoints;
    }

    try {
        const code = fs.readFileSync(inputFile, 'utf-8');
        const ast = esprima.parseScript(code, { tolerant: true });
        const endpoints = extractEndpoints(ast);
        console.log(JSON.stringify([...endpoints]));
    } catch (error) {
        console.error(`Error parsing ${inputFile}: ${error.message}`);
        process.exit(1);
    }
    ```

4.  **Set Up LinkFinder:**
    Download `linkfinder.py` from [https://github.com/GerbenJavado/LinkFinder](https://github.com/GerbenJavado/LinkFinder):
    ```cmd
    curl -o C:\LinkFinder\linkfinder.py [https://raw.githubusercontent.com/GerbenJavado/LinkFinder/master/linkfinder.py](https://raw.githubusercontent.com/GerbenJavado/LinkFinder/master/linkfinder.py)
    ```
    Verify:
    ```cmd
    dir C:\LinkFinder\linkfinder.py
    python C:\LinkFinder\linkfinder.py --help
    ```
    Alternatively, install as a module (if available):
    ```bash
    pip install git+[https://github.com/GerbenJavado/LinkFinder.git](https://github.com/GerbenJavado/LinkFinder.git)
    ```

5.  **GitHub Personal Access Token (Optional):**
    Generate a PAT at [https://github.com/settings/tokens](https://github.com/settings/tokens) with `repo` and `public_repo` scopes. Add it to `config.json` or enter it in the GUI.

## Usage

Run the Script:
```cmd
cd C:\Users\user\Documents\oHAR\oHAR-FINAL
python oJSS3.py
