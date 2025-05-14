import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import json
from datetime import datetime
from collections import deque
import subprocess
import tempfile
import sys
import fnmatch
import threading
import logging
import jsbeautifier
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.robotparser import RobotFileParser
import html
import webbrowser
import base64

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("extractor.log", mode="a", encoding="utf-8")
    ]
)

# Constants
DEFAULT_LINKFINDER_PATH = r"C:\LinkFinder\linkfinder.py"
DEFAULT_NODE_SCRIPT_PATH = r"C:\LinkFinder\parse_js.js"
CONFIG_FILE = "config.json"
NODE_NOT_FOUND_WARNING = "Node.js or parse_js.js not found. Falling back to jsbeautifier. Install Node.js and Esprima (npm install esprima) or check the script path."
GITHUB_API_BASE = "https://api.github.com"
GITHUB_SEARCH_RATE_LIMIT = 30
GITHUB_CACHE = {}
s3_status_cache = {}

# Common bucket prefixes
COMMON_BUCKET_PREFIXES = [
    "dev", "prod", "test", "staging", "backup", "data", "files", "public", "private", "logs"
]

# Regex for endpoints
regex = re.compile(
    r"""
    (?:"|')(
        (([a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']*) |
        ((/|\.\./|\./)[^"'><,;|*()%$^/\\\[\]][^"'><,;|()*()%$^/\\\[\]]+) |
        ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(php|asp|aspx|jsp|json|html|js|txt|xml)) |
        ([a-zA-Z0-9_\-]{1,}=\w+)
    )(?:"|')
    """,
    re.VERBOSE,
)

# Regex for S3 buckets
s3_regex = re.compile(
    r"(?:https?://)?(?:[a-z0-9\-]+\.)?s3[.-](?:[a-z0-9\-]+\.)?amazonaws\.com/([a-z0-9\-]+)|"
    r"(?:https?://)?([a-z0-9\-]+)\.s3[.-](?:[a-z0-9\-]+\.)?amazonaws\.com|"
    r"(?:https?://)?s3\.amazonaws\.com/([a-z0-9\-]+)|"
    r"(?:https?://)?([a-z0-9\-]+)\.s3-website[.-][a-z0-9\-]+\.amazonaws\.com",
    re.IGNORECASE
)

# Try to import LinkFinder
try:
    from linkfinder import main as linkfinder_main
except ImportError:
    linkfinder_main = None
    logging.warning("LinkFinder module not imported. Falling back to subprocess.")

# Config functions
def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return {
            "linkfinder_path": DEFAULT_LINKFINDER_PATH,
            "respect_robots": True,
            "github_pat": "",
            "node_script_path": DEFAULT_NODE_SCRIPT_PATH
        }
    except Exception as e:
        logging.error(f"Failed to load config: {str(e)}")
        return {
            "linkfinder_path": DEFAULT_LINKFINDER_PATH,
            "respect_robots": True,
            "github_pat": "",
            "node_script_path": DEFAULT_NODE_SCRIPT_PATH
        }

def save_config(config):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        logging.error(f"Failed to save config: {str(e)}")

# New: Parse sitemap
def parse_sitemap(base_url):
    """Fetch and parse sitemap URLs from a given base URL."""
    sitemap_urls = []
    try:
        sitemap_url = urljoin(base_url, "/sitemap.xml")
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        response = requests.get(sitemap_url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "xml")
        for loc in soup.find_all("loc"):
            url = loc.text.strip()
            if url:
                sitemap_urls.append(url)
        logging.info(f"Found {len(sitemap_urls)} URLs in sitemap: {sitemap_url}")
    except requests.RequestException as e:
        logging.warning(f"Failed to fetch sitemap {sitemap_url}: {str(e)}")
    return sitemap_urls

# New: Fetch URL content
def fetch_url_content(url, respect_robots=True):
    """Fetch content from a URL, respecting robots.txt if enabled."""
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # Check robots.txt
        if respect_robots:
            rp = RobotFileParser()
            robots_url = urljoin(base_url, "/robots.txt")
            try:
                rp.set_url(robots_url)
                rp.read()
                if not rp.can_fetch(headers["User-Agent"], url):
                    logging.warning(f"Robots.txt disallows crawling: {url}")
                    return None, "Disallowed by robots.txt"
            except Exception as e:
                logging.warning(f"Failed to parse robots.txt for {robots_url}: {str(e)}")

        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", "").lower()
        return response.text, content_type
    except requests.RequestException as e:
        logging.error(f"Failed to fetch {url}: {str(e)}")
        return None, str(e)

# New: Extract JS from HTML
def extract_js_from_html(html_content, base_url="", extract_urls=False):
    """Extract JavaScript code or URLs from HTML."""
    js_blocks = []
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        # Inline scripts
        for script in soup.find_all("script", src=False):
            if script.string:
                beautified = jsbeautifier.beautify(script.string.strip())
                if beautified:
                    js_blocks.append(beautified)
        # External scripts
        if extract_urls:
            for script in soup.find_all("script", src=True):
                src = script.get("src")
                if src:
                    absolute_url = urljoin(base_url, src)
                    if absolute_url.endswith(".js"):
                        js_blocks.append(absolute_url)
    except Exception as e:
        logging.error(f"Error extracting JS from HTML: {str(e)}")
    return js_blocks

# New: Filter JS files
def filter_js_files(js_urls, pattern):
    """Filter JavaScript URLs based on a pattern."""
    if not pattern:
        return js_urls
    return [url for url in js_urls if fnmatch.fnmatch(url, pattern)]

# New: Run LinkFinder
def run_linkfinder(input_path):
    """Run LinkFinder on a JavaScript file."""
    config = load_config()
    linkfinder_path = config.get("linkfinder_path", DEFAULT_LINKFINDER_PATH)
    endpoints = []
    
    if not os.path.exists(input_path):
        logging.error(f"Input file does not exist: {input_path}")
        return endpoints
    
    if linkfinder_main:
        try:
            endpoints = linkfinder_main(input_path)
            logging.info(f"LinkFinder module processed {input_path}, found {len(endpoints)} endpoints")
        except Exception as e:
            logging.error(f"LinkFinder module failed for {input_path}: {str(e)}")
    else:
        try:
            cmd = [sys.executable, linkfinder_path, "-i", input_path, "-o", "cli"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=30
            )
            output = result.stdout
            endpoints = [line.strip() for line in output.splitlines() if line.strip().startswith("http")]
            logging.info(f"LinkFinder subprocess processed {input_path}, found {len(endpoints)} endpoints")
        except subprocess.CalledProcessError as e:
            logging.error(f"LinkFinder subprocess failed for {input_path}: {e.stderr}")
        except subprocess.TimeoutExpired:
            logging.error(f"LinkFinder subprocess timed out for {input_path}")
        except Exception as e:
            logging.error(f"LinkFinder subprocess error: {str(e)}")
    
    return endpoints

# New: Extract endpoints
def extract_endpoints(content, file_ext=""):
    """Extract endpoints using regex."""
    endpoints = []
    try:
        beautified = content if file_ext != ".js" else jsbeautifier.beautify(content)
        matches = regex.findall(beautified)
        for match in matches:
            endpoint = match[0]
            if endpoint and not endpoint.startswith(("'", '"')):
                endpoints.append(endpoint)
    except Exception as e:
        logging.error(f"Error extracting endpoints: {str(e)}")
    return sorted(set(endpoints))

# New: Test S3 public access
def test_s3_public_access(bucket_url, bucket_name):
    """Test if an S3 bucket is publicly accessible."""
    if bucket_url in s3_status_cache:
        return s3_status_cache[bucket_url]
    
    access = {"listing": "Not Listable", "readable": "Not Readable", "details": ""}
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        # Test bucket listing
        response = requests.get(bucket_url, headers=headers, timeout=10)
        if response.status_code == 200 and "<ListBucketResult" in response.text:
            access["listing"] = "Listable"
            access["details"] = "Bucket listing is publicly accessible."
        elif response.status_code == 200:
            access["readable"] = "Readable"
            access["details"] = "Bucket content is publicly accessible."
        else:
            access["details"] = f"HTTP {response.status_code}: Access denied or bucket does not exist."
    except requests.RequestException as e:
        access["details"] = f"Error testing access: {str(e)}"
    
    s3_status_cache[bucket_url] = access
    return access

# New: Export S3 results
def export_s3_results(s3_buckets):
    """Export S3 bucket results to a file."""
    if not s3_buckets:
        messagebox.showinfo("Export", "No S3 buckets to export.")
        return
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if file_path:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                for bucket_name, bucket_url in s3_buckets:
                    access = test_s3_public_access(bucket_url, bucket_name)
                    f.write(f"Bucket: {bucket_name}\nURL: {bucket_url}\nListing: {access['listing']}\nReadable: {access['readable']}\nDetails: {access['details']}\n\n")
            messagebox.showinfo("Export", f"S3 results exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export S3 results: {str(e)}")

# New: Export all results
def export_all_results(input_val, endpoints, s3_buckets, js_endpoints):
    """Export all results to a JSON file."""
    if not (endpoints or s3_buckets or js_endpoints):
        messagebox.showinfo("Export", "No results to export.")
        return
    file_path = filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
    )
    if file_path:
        try:
            data = {
                "input": input_val,
                "timestamp": datetime.now().isoformat(),
                "endpoints": endpoints,
                "s3_buckets": [
                    {
                        "name": name,
                        "url": url,
                        "access": test_s3_public_access(url, name)
                    } for name, url in s3_buckets
                ],
                "js_endpoints": {k: v for k, v in js_endpoints.items()}
            }
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            messagebox.showinfo("Export", f"Results exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results: {str(e)}")

# New: Export JS endpoints
def export_js_endpoints(js_endpoints):
    """Export JavaScript endpoints to a file."""
    if not js_endpoints:
        messagebox.showinfo("Export", "No JavaScript endpoints to export.")
        return
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if file_path:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                for js_file, endpoints in js_endpoints.items():
                    f.write(f"File: {js_file}\n")
                    if endpoints:
                        f.write("\n".join(f"  {ep}" for ep in endpoints) + "\n")
                    else:
                        f.write("  No endpoints found.\n")
                    f.write("\n")
            messagebox.showinfo("Export", f"JS endpoints exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export JS endpoints: {str(e)}")

# New: Export HTML report
def export_html_report(input_val, endpoints, s3_buckets, js_endpoints):
    """Export results to an HTML report."""
    if not (endpoints or s3_buckets or js_endpoints):
        messagebox.showinfo("Export", "No results to export.")
        return
    file_path = filedialog.asksaveasfilename(
        defaultextension=".html",
        filetypes=[("HTML Files", "*.html"), ("All Files", "*.*")]
    )
    if file_path:
        try:
            html_content = f"""
            <html>
            <head>
                <title>S3 Bucket and Endpoint Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #333; }}
                    h2 {{ color: #555; }}
                    pre {{ background: #f4f4f4; padding: 10px; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <h1>S3 Bucket and Endpoint Report</h1>
                <p><strong>Input:</strong> {html.escape(input_val)}</p>
                <p><strong>Timestamp:</strong> {datetime.now().isoformat()}</p>
                <h2>JavaScript Files and Endpoints</h2>
                <pre>
            """
            if js_endpoints:
                for js_file, eps in js_endpoints.items():
                    html_content += f"File: {html.escape(js_file)}\n"
                    if eps:
                        html_content += "\n".join(f"  {html.escape(ep)}" for ep in eps) + "\n"
                    else:
                        html_content += "  No endpoints found.\n"
                    html_content += "\n"
            else:
                html_content += "No JavaScript files processed.\n"
            
            html_content += """
                </pre>
                <h2>All Endpoints</h2>
                <pre>
            """
            if endpoints:
                html_content += "\n".join(html.escape(ep) for ep in endpoints) + "\n"
            else:
                html_content += "No endpoints found.\n"
            
            html_content += """
                </pre>
                <h2>S3 Buckets</h2>
                <pre>
            """
            if s3_buckets:
                for name, url in s3_buckets:
                    access = test_s3_public_access(url, name)
                    html_content += (
                        f"Bucket: {html.escape(name)}\n"
                        f"URL: {html.escape(url)}\n"
                        f"Listing: {html.escape(access['listing'])}\n"
                        f"Readable: {html.escape(access['readable'])}\n"
                        f"Details: {html.escape(access['details'])}\n\n"
                    )
            else:
                html_content += "No S3 buckets found.\n"
            
            html_content += """
                </pre>
            </body>
            </html>
            """
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            messagebox.showinfo("Export", f"HTML report exported to {file_path}")
            webbrowser.open(f"file://{os.path.abspath(file_path)}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export HTML report: {str(e)}")

# New: Browse file
def on_browse(entry):
    """Browse for input file."""
    path = filedialog.askopenfilename(
        filetypes=[("All Files", "*.*"), ("JavaScript Files", "*.js"), ("HTML Files", "*.html")]
    )
    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)

# New: Browse LinkFinder
def on_browse_linkfinder(entry):
    """Browse for LinkFinder script."""
    path = filedialog.askopenfilename(
        filetypes=[("Python Files", "*.py"), ("All Files", "*.*")],
        initialfile="linkfinder.py"
    )
    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)
        config = load_config()
        config["linkfinder_path"] = path
        save_config(config)

# New: Browse Node.js script
def on_browse_node_script(entry):
    """Browse for Node.js parser script."""
    path = filedialog.askopenfilename(
        filetypes=[("JavaScript Files", "*.js"), ("All Files", "*.*")],
        initialfile="parse_js.js"
    )
    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)
        config = load_config()
        config["node_script_path"] = path
        save_config(config)

# New: Generate bucket names
def generate_bucket_names(target):
    """Generate potential S3 bucket names based on target."""
    bucket_names = []
    parsed = urlparse(target) if target.startswith("http") else None
    base_name = parsed.netloc.split('.')[0] if parsed else os.path.splitext(os.path.basename(target))[0]
    for prefix in COMMON_BUCKET_PREFIXES + [""]:
        for suffix in COMMON_BUCKET_PREFIXES + [""]:
            if prefix or suffix:
                name = f"{prefix}{base_name}{suffix}".strip("-")
                bucket_names.append(name)
    return sorted(set(bucket_names))

# New: Validate bucket name
def validate_bucket_name(name):
    """Validate S3 bucket name per AWS naming rules."""
    if not name or len(name) < 3 or len(name) > 63:
        return False
    if not re.match(r'^[a-z0-9][a-z0-9.-]*[a-z0-9]$', name):
        return False
    if '..' in name or '.-' in name or '-.' in name:
        return False
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', name):
        return False
    return True

# New: Search GitHub for buckets
def search_github_for_buckets(target, github_pat, max_results=100):
    """Search GitHub for S3 bucket names using the Search API."""
    if not github_pat:
        logging.warning("GitHub PAT not provided; skipping GitHub search.")
        return []

    parsed = urlparse(target) if target.startswith("http") else None
    base_name = parsed.netloc.split('.')[0] if parsed else os.path.splitext(os.path.basename(target))[0]
    search_terms = [base_name] + COMMON_BUCKET_PREFIXES
    s3_buckets = []
    seen_names = set()

    cache_key = f"{target}:{','.join(search_terms)}"
    if cache_key in GITHUB_CACHE:
        logging.info(f"Using cached GitHub results for {cache_key}")
        return GITHUB_CACHE[cache_key]

    headers = {
        "Authorization": f"Bearer {github_pat}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "S3-Bucket-Extractor/1.0"
    }

    for term in search_terms:
        query = f'"{term} s3.amazonaws.com" OR "s3://{term}"'
        params = {
            "q": query,
            "per_page": min(max_results, 100),
            "page": 1
        }
        url = f"{GITHUB_API_BASE}/search/code"

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 403 and "rate limit" in response.text.lower():
                logging.error("GitHub API rate limit exceeded. Try again later or use a different PAT.")
                break
            response.raise_for_status()
            data = response.json()

            if data.get("incomplete_results"):
                logging.warning(f"Incomplete GitHub search results for query: {query}")

            for item in data.get("items", []):
                repo = item["repository"]["full_name"]
                path = item["path"]
                file_url = item["url"]
                file_response = requests.get(file_url, headers=headers, timeout=10)
                if file_response.status_code != 200:
                    logging.warning(f"Failed to fetch file {path} from {repo}")
                    continue
                file_data = file_response.json()
                if "content" not in file_data:
                    continue
                try:
                    content = base64.b64decode(file_data["content"]).decode("utf-8", errors="ignore")
                except Exception as e:
                    logging.warning(f"Failed to decode content from {path}: {str(e)}")
                    continue

                matches = s3_regex.findall(content)
                for match in matches:
                    bucket_name = next((m for m in match if m), None)
                    if bucket_name and validate_bucket_name(bucket_name) and bucket_name not in seen_names:
                        bucket_url = f"https://{bucket_name}.s3.amazonaws.com"
                        s3_buckets.append((bucket_name, bucket_url))
                        seen_names.add(bucket_name)

            remaining = int(response.headers.get("X-RateLimit-Remaining", 0))
            if remaining < 5:
                logging.warning("GitHub API rate limit nearly exhausted. Pausing search.")
                break

        except requests.RequestException as e:
            logging.error(f"GitHub API error for query {query}: {str(e)}")
            continue

    GITHUB_CACHE[cache_key] = s3_buckets
    logging.info(f"Found {len(s3_buckets)} potential S3 buckets via GitHub search")
    return s3_buckets

# New: Extract S3 buckets
def extract_s3_buckets(endpoints, target="", github_pat="", use_github_search=False):
    """Extract and generate S3 buckets, including GitHub search results."""
    s3_buckets = []
    seen_names = set()
    
    for endpoint in endpoints:
        matches = s3_regex.findall(endpoint)
        for match in matches:
            bucket_name = next((m for m in match if m), None)
            if bucket_name and validate_bucket_name(bucket_name) and bucket_name not in seen_names:
                s3_buckets.append((bucket_name, endpoint))
                seen_names.add(bucket_name)
    
    generated_names = generate_bucket_names(target)
    for name in generated_names:
        if name not in seen_names and validate_bucket_name(name):
            for url_format in [
                f"https://{name}.s3.amazonaws.com",
                f"https://s3.amazonaws.com/{name}",
                f"https://{name}.s3.us-east-1.amazonaws.com"
            ]:
                s3_buckets.append((name, url_format))
                seen_names.add(name)
    
    if use_github_search and github_pat:
        github_buckets = search_github_for_buckets(target, github_pat)
        for bucket_name, bucket_url in github_buckets:
            if bucket_name not in seen_names:
                s3_buckets.append((bucket_name, bucket_url))
                seen_names.add(bucket_name)
    
    return sorted(s3_buckets, key=lambda x: x[0])

# Esprima parser
def run_esprima_parser(input_path, node_script_path):
    """Run Node.js Esprima parser on a JavaScript file."""
    if not os.path.exists(input_path):
        logging.error(f"Invalid input path for Esprima: {input_path}")
        return []
    
    if not os.path.exists(node_script_path):
        logging.error(f"Node.js script not found at: {node_script_path}")
        return []
    
    try:
        input_path = os.path.normpath(input_path)
        node_script_path = os.path.normpath(node_script_path)
        cmd = ["node", node_script_path, input_path]
        logging.debug(f"Executing Esprima subprocess: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=30
        )
        try:
            endpoints = json.loads(result.stdout)
            return [ep for ep in endpoints if isinstance(ep, str) and ep.strip()]
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON output from Esprima: {str(e)}")
            return []
    except subprocess.CalledProcessError as e:
        logging.error(f"Esprima subprocess failed: {e.stderr}")
        return []
    except subprocess.TimeoutExpired:
        logging.error(f"Esprima subprocess timed out for {input_path}")
        return []
    except Exception as e:
        logging.error(f"Esprima subprocess error: {str(e)}")
        return []

# Analyze input
def analyze_input(input_str, include_all_linked=False, crawl_depth=0, use_linkfinder=False, js_filter="", max_pages=100, respect_robots=True, progress_var=None, progress_bar=None, github_pat="", use_github_search=False, use_esprima=False, node_script_path=DEFAULT_NODE_SCRIPT_PATH):
    """Analyze input to extract endpoints and S3 buckets."""
    endpoints = []
    s3_buckets = []
    js_endpoints = {}
    
    def process_js_content(js_code, source, file_ext=".js"):
        """Process JavaScript content with Esprima or fallback."""
        current_endpoints = []
        if use_esprima and file_ext == ".js":
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".js", mode='w', encoding='utf-8') as temp_js:
                    temp_js.write(js_code)
                    temp_js_path = temp_js.name
                if os.path.exists(temp_js_path) and os.path.getsize(temp_js_path) > 0:
                    logging.debug(f"Created temporary JS file for Esprima: {temp_js_path}")
                    esprima_endpoints = run_esprima_parser(temp_js_path, node_script_path)
                    current_endpoints.extend(esprima_endpoints)
                    js_endpoints[source] = sorted(set(esprima_endpoints))
                else:
                    logging.warning(f"Temporary JS file {temp_js_path} is empty or not created")
            except Exception as e:
                logging.error(f"Esprima processing failed for {source}: {str(e)}")
                current_endpoints.extend(extract_endpoints(js_code, file_ext))
            finally:
                if 'temp_js_path' in locals() and os.path.exists(temp_js_path):
                    try:
                        os.unlink(temp_js_path)
                        logging.debug(f"Deleted temporary JS file: {temp_js_path}")
                    except Exception as e:
                        logging.error(f"Failed to delete temporary file {temp_js_path}: {str(e)}")
        else:
            current_endpoints.extend(extract_endpoints(js_code, file_ext))
        
        if use_linkfinder and file_ext == ".js":
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".js", mode='w', encoding='utf-8') as temp_js:
                    temp_js.write(js_code)
                    temp_js_path = temp_js.name
                if os.path.exists(temp_js_path) and os.path.getsize(temp_js_path) > 0:
                    lf_endpoints = run_linkfinder(temp_js_path)
                    current_endpoints.extend(lf_endpoints)
                    if source in js_endpoints:
                        js_endpoints[source].extend(lf_endpoints)
                        js_endpoints[source] = sorted(set(js_endpoints[source]))
                    else:
                        js_endpoints[source] = sorted(set(lf_endpoints))
            except Exception as e:
                logging.error(f"LinkFinder processing failed for {source}: {str(e)}")
            finally:
                if 'temp_js_path' in locals() and os.path.exists(temp_js_path):
                    try:
                        os.unlink(temp_js_path)
                    except Exception as e:
                        logging.error(f"Failed to delete temporary file {temp_js_path}: {str(e)}")
        
        return current_endpoints

    if os.path.isfile(input_str):
        try:
            with open(input_str, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                if not content.strip():
                    logging.warning(f"Empty file content: {input_str}")
                    return [], [], {}
                file_ext = os.path.splitext(input_str)[1].lower()
                if file_ext == ".html":
                    js_blocks = extract_js_from_html(content)
                    content = "\n".join(js_blocks)
                current_endpoints = process_js_content(content, input_str, file_ext)
                endpoints.extend(current_endpoints)
                s3_buckets = extract_s3_buckets(endpoints, input_str, github_pat, use_github_search)
        except Exception as e:
            logging.error(f"File processing error for {input_str}: {str(e)}")
            messagebox.showerror("File Error", str(e))
            return [], [], {}
    elif input_str.startswith("http"):
        visited = set()
        queue = deque([(input_str, 0)])
        to_process = [(input_str, 0)]
        base_domain = urlparse(input_str).netloc
        all_js_files = []
        page_count = 0

        sitemap_urls = parse_sitemap(input_str)
        for s_url in sitemap_urls:
            if urlparse(s_url).netloc == base_domain and s_url not in visited:
                queue.append((s_url, 0))
                to_process.append((s_url, 0))

        with ThreadPoolExecutor(max_workers=5) as executor:
            while queue and page_count < max_pages:
                url, depth = queue.popleft()
                if url in visited or depth > crawl_depth:
                    continue
                visited.add(url)
                page_count += 1

                future = executor.submit(fetch_url_content, url, respect_robots)
                html_content, info = future.result()
                if html_content is None:
                    logging.warning(f"Skipping {url} due to fetch failure: {info}")
                    continue

                current_endpoints = []
                file_ext = ".html" if "html" in info.lower() else ".js" if "javascript" in info.lower() else ""
                if file_ext == ".html":
                    js_blocks = extract_js_from_html(html_content, url, extract_urls=include_all_linked)
                    linked_sources = [s for s in js_blocks if s.startswith("http") and s.endswith(".js")]
                    inline_scripts = [s for s in js_blocks if not s.startswith("http")]

                    for script in inline_scripts:
                        current_endpoints.extend(process_js_content(script, f"{url}:inline", ".js"))

                    if include_all_linked and linked_sources:
                        filtered_js_files = filter_js_files(linked_sources, js_filter)
                        logging.info(f"Found {len(linked_sources)} JS files, {len(filtered_js_files)} after filtering with pattern '{js_filter}'")
                        if not filtered_js_files:
                            logging.warning("No JS files matched the filter pattern.")

                        futures = [executor.submit(fetch_url_content, js_url, respect_robots) for js_url in filtered_js_files]
                        for future, js_url in zip(as_completed(futures), filtered_js_files):
                            js_code, content_type = future.result()
                            if js_code and "javascript" in content_type.lower():
                                js_file_endpoints = process_js_content(js_code, js_url, ".js")
                                current_endpoints.extend(js_file_endpoints)
                                all_js_files.append(js_url)
                else:
                    current_endpoints = process_js_content(html_content, url, file_ext)
                    all_js_files.append(url)

                endpoints.extend(current_endpoints)

                if progress_var and progress_bar:
                    processed = len(visited)
                    total = len(to_process)
                    progress_var.set((processed / max(total, 1)) * 100)
                    progress_bar.update()

        endpoints = sorted(set(endpoints))
        s3_buckets = extract_s3_buckets(endpoints, input_str, github_pat, use_github_search)
        logging.info(f"Processed {len(all_js_files)} JS files, found {len(endpoints)} total endpoints")
    else:
        messagebox.showerror("Invalid Input", "Please enter a valid file path or URL.")
        return [], [], {}

    return endpoints, s3_buckets, js_endpoints

# GUI
def create_gui():
    root = tk.Tk()
    root.title("S3 Bucket and Endpoint Extractor with LinkFinder and GitHub Search")
    root.geometry("900x850")

    config_frame = tk.Frame(root)
    config_frame.pack(padx=10, pady=5, fill=tk.X)
    
    tk.Label(config_frame, text="LinkFinder Path:").pack(side=tk.LEFT)
    config = load_config()
    linkfinder_entry = tk.Entry(config_frame, width=20)
    linkfinder_entry.insert(0, config.get("linkfinder_path", DEFAULT_LINKFINDER_PATH))
    linkfinder_entry.pack(side=tk.LEFT, padx=(0, 5))
    browse_linkfinder_btn = tk.Button(config_frame, text="Browse", command=lambda: on_browse_linkfinder(linkfinder_entry))
    browse_linkfinder_btn.pack(side=tk.LEFT)
    
    tk.Label(config_frame, text="Node.js Script:").pack(side=tk.LEFT, padx=5)
    node_script_entry = tk.Entry(config_frame, width=20)
    node_script_entry.insert(0, config.get("node_script_path", DEFAULT_NODE_SCRIPT_PATH))
    node_script_entry.pack(side=tk.LEFT, padx=(0, 5))
    browse_node_btn = tk.Button(config_frame, text="Browse", command=lambda: on_browse_node_script(node_script_entry))
    browse_node_btn.pack(side=tk.LEFT)
    
    tk.Label(config_frame, text="GitHub PAT:").pack(side=tk.LEFT, padx=5)
    github_pat_entry = tk.Entry(config_frame, width=20, show="*")
    github_pat_entry.insert(0, config.get("github_pat", ""))
    github_pat_entry.pack(side=tk.LEFT, padx=(0, 5))

    input_frame = tk.Frame(root)
    input_frame.pack(padx=10, pady=5, fill=tk.X)
    tk.Label(input_frame, text="URL/File:").pack(side=tk.LEFT)
    entry = tk.Entry(input_frame, width=50)
    entry.pack(side=tk.LEFT, padx=(0, 5), expand=True, fill=tk.X)
    browse_btn = tk.Button(input_frame, text="Browse", command=lambda: on_browse(entry))
    browse_btn.pack(side=tk.LEFT)

    crawl_frame = tk.Frame(root)
    crawl_frame.pack(padx=10, pady=5, fill=tk.X)
    tk.Label(crawl_frame, text="Crawl Depth:").pack(side=tk.LEFT)
    depth_entry = tk.Spinbox(crawl_frame, from_=0, to=10, width=5)
    depth_entry.pack(side=tk.LEFT, padx=5)
    tk.Label(crawl_frame, text="Max Pages:").pack(side=tk.LEFT, padx=5)
    max_pages_entry = tk.Spinbox(crawl_frame, from_=1, to=1000, width=5)
    max_pages_entry.delete(0, tk.END)
    max_pages_entry.insert(0, "100")
    max_pages_entry.pack(side=tk.LEFT, padx=5)
    tk.Label(crawl_frame, text="(Depth 0 = input only; Max pages limits crawl)").pack(side=tk.LEFT)

    js_filter_frame = tk.Frame(root)
    js_filter_frame.pack(padx=10, pady=5, fill=tk.X)
    tk.Label(js_filter_frame, text="JS File Filter (e.g., *.min.js):").pack(side=tk.LEFT)
    js_filter_entry = tk.Entry(js_filter_frame, width=20)
    js_filter_entry.pack(side=tk.LEFT, padx=5)
    tk.Label(js_filter_frame, text="(Leave blank for all JS files)").pack(side=tk.LEFT)

    options_frame = tk.Frame(root)
    options_frame.pack(padx=10, pady=5, fill=tk.X)
    linkfinder_var = tk.BooleanVar(value=False)
    tk.Checkbutton(
        options_frame,
        text="Use LinkFinder for JS endpoint extraction",
        variable=linkfinder_var
    ).pack(side=tk.LEFT, padx=5)
    respect_robots_var = tk.BooleanVar(value=config.get("respect_robots", True))
    tk.Checkbutton(
        options_frame,
        text="Respect robots.txt (recommended for ethical crawling)",
        variable=respect_robots_var
    ).pack(side=tk.LEFT, padx=5)
    use_github_search_var = tk.BooleanVar(value=False)
    tk.Checkbutton(
        options_frame,
        text="Search GitHub for S3 buckets (requires PAT, use ethically)",
        variable=use_github_search_var
    ).pack(side=tk.LEFT, padx=5)
    use_esprima_var = tk.BooleanVar(value=False)
    tk.Checkbutton(
        options_frame,
        text="Use Esprima for advanced JS parsing (requires Node.js)",
        variable=use_esprima_var
    ).pack(side=tk.LEFT, padx=5)

    def on_extract(entry, output_area, progress_var, progress_bar, depth_entry, linkfinder_var, js_filter_entry, max_pages_entry, respect_robots_var, include_all_linked=False):
        input_val = entry.get().strip()
        github_pat = github_pat_entry.get().strip()
        node_script_path = node_script_entry.get().strip()
        try:
            crawl_depth = int(depth_entry.get())
            if crawl_depth < 0:
                raise ValueError("Crawl depth must be non-negative.")
            max_pages = int(max_pages_entry.get())
            if max_pages <= 0:
                raise ValueError("Max pages must be positive.")
        except ValueError as e:
            messagebox.showerror("Invalid Input", str(e))
            return

        if not input_val:
            messagebox.showerror("Error", "Please enter a URL or file path.")
            return

        config = load_config()
        config["github_pat"] = github_pat
        config["node_script_path"] = node_script_path
        save_config(config)
        
        use_linkfinder = linkfinder_var.get() and (bool(linkfinder_main) or os.path.exists(config.get("linkfinder_path", DEFAULT_LINKFINDER_PATH)))
        if linkfinder_var.get() and not use_linkfinder:
            messagebox.showwarning(
                "LinkFinder Not Available",
                "LinkFinder is not installed or not found at the specified path. Falling back to default regex extraction."
            )

        use_esprima = use_esprima_var.get() and os.path.exists(node_script_path)
        if use_esprima_var.get() and not use_esprima:
            messagebox.showwarning(
                "Esprima Not Available",
                NODE_NOT_FOUND_WARNING
            )

        js_filter = js_filter_entry.get().strip()
        respect_robots = respect_robots_var.get()
        use_github_search = use_github_search_var.get()

        def extraction_task():
            output_area.delete(1.0, tk.END)
            endpoints, s3_buckets, js_endpoints = analyze_input(
                input_val,
                include_all_linked=include_all_linked,
                crawl_depth=crawl_depth,
                use_linkfinder=use_linkfinder,
                js_filter=js_filter,
                max_pages=max_pages,
                respect_robots=respect_robots,
                progress_var=progress_var,
                progress_bar=progress_bar,
                github_pat=github_pat,
                use_github_search=use_github_search,
                use_esprima=use_esprima,
                node_script_path=node_script_path
            )

            output_area.insert(tk.END, "=== JavaScript Files and Endpoints ===\n")
            if js_endpoints:
                for js_file, eps in js_endpoints.items():
                    output_area.insert(tk.END, f"\nFile: {js_file}\n")
                    if eps:
                        output_area.insert(tk.END, "\n".join(f"  {ep}" for ep in eps) + "\n")
                    else:
                        output_area.insert(tk.END, "  No endpoints found.\n")
            else:
                output_area.insert(tk.END, "No JavaScript files processed.\n")
            output_area.insert(tk.END, "\n=== All Endpoints ===\n")
            if endpoints:
                output_area.insert(tk.END, "\n".join(endpoints) + "\n")
            else:
                output_area.insert(tk.END, "No endpoints found.\n")
            output_area.insert(tk.END, "\n=== S3 Buckets ===\n")
            if s3_buckets:
                for bucket_name, bucket_url in s3_buckets:
                    access = test_s3_public_access(bucket_url, bucket_name)
                    output_area.insert(tk.END, f"Bucket: {bucket_name}\nURL: {bucket_url}\nListing: {access['listing']}\nReadable: {access['readable']}\nDetails: {access['details']}\n\n")
            else:
                output_area.insert(tk.END, "No S3 buckets found.\n")

            export_s3_btn.data = s3_buckets
            export_all_btn.data = (input_val, endpoints, s3_buckets, js_endpoints)
            export_js_btn.data = js_endpoints
            export_html_btn.data = (input_val, endpoints, s3_buckets, js_endpoints)

            export_s3_btn.config(state=tk.NORMAL if s3_buckets else tk.DISABLED)
            export_all_btn.config(state=tk.NORMAL if endpoints or s3_buckets or js_endpoints else tk.DISABLED)
            export_js_btn.config(state=tk.NORMAL if js_endpoints else tk.DISABLED)
            export_html_btn.config(state=tk.NORMAL if endpoints or s3_buckets or js_endpoints else tk.DISABLED)

            progress_var.set(0)
            progress_bar.update()

        threading.Thread(target=extraction_task, daemon=True).start()

    button_frame = tk.Frame(root)
    button_frame.pack(pady=5)
    global export_s3_btn, export_all_btn, export_js_btn, export_html_btn
    extract_btn = tk.Button(
        button_frame,
        text="Extract Inline",
        command=lambda: on_extract(entry, output_area, progress_var, progress_bar, depth_entry, linkfinder_var, js_filter_entry, max_pages_entry, respect_robots_var, False)
    )
    extract_btn.pack(side=tk.LEFT, padx=5)
    extract_all_btn = tk.Button(
        button_frame,
        text="Extract All JS (linked too)",
        command=lambda: on_extract(entry, output_area, progress_var, progress_bar, depth_entry, linkfinder_var, js_filter_entry, max_pages_entry, respect_robots_var, True)
    )
    extract_all_btn.pack(side=tk.LEFT, padx=5)
    export_s3_btn = tk.Button(button_frame, text="Export S3 Results", state=tk.DISABLED,
                              command=lambda: export_s3_results(getattr(export_s3_btn, 'data', [])))
    export_s3_btn.pack(side=tk.LEFT, padx=5)
    export_all_btn = tk.Button(
        button_frame,
        text="Export JSON",
        state=tk.DISABLED,
        command=lambda: export_all_results(*getattr(export_all_btn, 'data', ('', [], [], {})))
    )
    export_all_btn.pack(side=tk.LEFT, padx=5)
    export_js_btn = tk.Button(
        button_frame,
        text="Export JS Endpoints",
        state=tk.DISABLED,
        command=lambda: export_js_endpoints(getattr(export_js_btn, 'data', {})))
    export_js_btn.pack(side=tk.LEFT, padx=5)
    export_html_btn = tk.Button(
        button_frame,
        text="Export HTML Report",
        state=tk.DISABLED,
        command=lambda: export_html_report(*getattr(export_html_btn, 'data', ('', [], [], {})))
    )
    export_html_btn.pack(side=tk.LEFT, padx=5)

    progress_var = tk.DoubleVar()
    progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100)
    progress_bar.pack(fill=tk.X, padx=10, pady=5)

    output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=25)
    output_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
