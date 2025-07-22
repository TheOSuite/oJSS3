# oJSS3.py - Endpoint and S3 Bucket Extractor

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/github/license/TheOSuite/oJSS3)
![Build](https://img.shields.io/badge/Build-Passing-brightgreen)

This Python script is a versatile tool for web reconnaissance, capable of extracting potential API endpoints and identifying Amazon S3 buckets from various sources. It can process local files (HTML/JS), crawl websites, and perform subdomain discovery.

## Features

  * **Endpoint Extraction:** Identifies potential API endpoints using regular expressions and optionally LinkFinder from HTML and JavaScript content.
  * **S3 Bucket Identification:** Extracts potential S3 bucket names found within scanned content and can optionally generate common bucket names based on the target.
  * **Website Crawling:** Fetches and processes content from a given URL and its linked pages up to a specified depth.
  * **JavaScript Analysis:** Extracts and analyzes inline and linked JavaScript files for endpoints.
  * **Subdomain Discovery:** Includes methods for discovering subdomains using Certificate Transparency logs, DNS databases, SecurityTrails API (requires API key), bruteforce (requires wordlist), and zone transfer attempts.
  * **Configurable Options:** Allows setting paths for external tools (LinkFinder, Node.js script for Esprima), respecting `robots.txt`, and using a GitHub Personal Access Token (PAT) for GitHub searches.
  * **Export Options:** Supports exporting results to text files (S3 buckets, JS endpoints, subdomains), JSON, and HTML reports.
  * **GUI Interface:** Provides a graphical user interface for ease of use.

## Installation

1.  **Clone the repository (if applicable):** If `oJSS3.py` is part of a larger repository, clone it. Otherwise, just download the `oJSS3.py` file.
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```
2.  **Install Python Dependencies:** The script requires several Python libraries. It is recommended to use a virtual environment.
    ```bash
    pip install -r requirements.txt
    ```
3.  **Install LinkFinder (Optional):** For enhanced JavaScript endpoint extraction, you can install LinkFinder.
    ```bash
    git clone https://github.com/GerbenJaveld/LinkFinder.git
    cd LinkFinder
    pip install -r requirements.txt
    python setup.py install
    ```
    Update the `LinkFinder Path` in the script's configuration or GUI to point to the `linkfinder.py` file.
4.  **Install Node.js and Esprima (Optional):** For advanced JavaScript parsing using Esprima, you need Node.js and the Esprima library.
    ```bash
    # Install Node.js from https://nodejs.org/
    npm install -g esprima
    ```
    Update the `Node.js Script` path in the script's configuration or GUI to point to the `parse_js.js` file (this file was not included in the provided content, you may need to create or obtain it separately if using the Esprima feature).
5.  **Wordlist for Bruteforce (Optional):** For subdomain bruteforce, you can provide a custom wordlist or use the default one created by the script if none is specified (`wordlist.txt` in the script's directory).

## Usage

The script primarily operates through a GUI.

1.  **Run the script:**

    ```bash
    python oJSS3.py
    ```

2.  **Endpoint Discovery Tab:**

      * Enter a URL or browse for a local HTML/JS file in the "URL/File" field.
      * Adjust "Crawl Depth" (0 for input only, \>0 for crawling linked pages) and "Max Pages" (limit for crawling).
      * Optionally, specify a "JS File Filter" (e.g., `*.min.js`) to process only matching JavaScript files when crawling.
      * Check "Use LinkFinder" to use the LinkFinder script for JS analysis (requires LinkFinder installed).
      * Check "Respect robots.txt" to obey website crawling rules (recommended).
      * Check "Search GitHub for S3 buckets" to search GitHub code for S3 buckets related to the target (requires a GitHub PAT).
      * Check "Use Esprima for advanced JS parsing" for potentially better JS analysis (requires Node.js and Esprima setup).
      * Check "Generate potential S3 bucket names" to include programmatically generated bucket names in the results.
      * Click "Extract Inline" to process only the initial input.
      * Click "Extract All JS (linked too)" to process the input and linked JavaScript files (up to crawl depth and max pages).
      * Results will appear in the output area.
      * Use the Export buttons to save the results in various formats.

3.  **Subdomain Discovery Tab:**

      * Enter a domain name (e.g., `example.com`) in the "Domain" field.
      * Select the desired "Discovery Methods" (Certificate Transparency, DNS Databases, SecurityTrails API, Bruteforce, Zone Transfer).
      * If using the SecurityTrails API, enter your "SecurityTrails API Key".
      * If using Bruteforce, specify the "Bruteforce Wordlist" file.
      * Click "Discover Subdomains".
      * Discovered subdomains will appear in the output area.
      * Use the Export button to save the subdomains to a file.
      * Click "Analyze Subdomains" to check the liveness of the discovered subdomains.
      * Click "Send to Main Tool" to select discovered subdomains and send one to the main "URL/File" input field for further analysis.

4.  **Consolidated Results Tab:**

      * This tab displays the combined results from the last endpoint or subdomain discovery task.

## Configuration

Configuration is saved in a `config.json` file in the same directory as the script. You can modify the following settings via the GUI:

  * `linkfinder_path`: Path to the `linkfinder.py` script.
  * `respect_robots`: Boolean indicating whether to respect `robots.txt`.
  * `github_pat`: Your GitHub Personal Access Token for GitHub searches.
  * `node_script_path`: Path to the Node.js script for Esprima parsing (e.g., `parse_js.js`).

A cache for GitHub search results is stored in `github_cache.pkl`.

## Examples

**Example 1: Extracting endpoints from a single JavaScript file**

1.  Open the GUI.
2.  In the "Endpoint Discovery" tab, click "Browse" and select your JavaScript file (e.g., `script.js`).
3.  Click "Extract Inline".
4.  The extracted endpoints will appear in the output area.

**Example 2: Crawling a website and extracting all linked JS endpoints**

1.  Open the GUI.
2.  In the "Endpoint Discovery" tab, enter a URL (e.g., `https://example.com`).
3.  Set "Crawl Depth" to the desired level (e.g., 1 or 2).
4.  Optionally, set "Max Pages" to limit the crawl.
5.  Check "Use LinkFinder" or "Use Esprima" if you have them set up for better JS analysis.
6.  Click "Extract All JS (linked too)".
7.  The script will crawl the site and extract endpoints from the main page and linked JavaScript files.

**Example 3: Discovering subdomains for a domain**

1.  Open the GUI.
2.  Go to the "Subdomain Discovery" tab.
3.  Enter the target domain (e.g., `targetdomain.com`).
4.  Select the desired discovery methods.
5.  Click "Discover Subdomains".
6.  The discovered subdomains will be listed in the output area.

**Example 4: Exporting results**

1.  After running an extraction or discovery task, click the relevant Export button (e.g., "Export JSON", "Export HTML Report") to save the results to a file.

## Ethical Considerations and Responsible Use

This tool can be used for security testing and web reconnaissance. Always ensure you have explicit permission before scanning any website or system you do not own or control. Respect `robots.txt` files and be mindful of the load your scanning activities place on target servers. When using the GitHub search feature, be aware of rate limits and use a Personal Access Token responsibly.

Remember that unauthorized access and scanning can be illegal and unethical. Use this tool responsibly and only on targets you are authorized to test.
