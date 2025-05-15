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
import socket
import dns.resolver
import dns.zone
import dns.query
import xml.etree.ElementTree as ET
from typing import List, Tuple, Dict, Set, Optional
from tenacity import retry, stop_after_attempt, wait_exponential
import pickle
import asyncio
import aiohttp
import aiodns

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
CACHE_FILE = "github_cache.pkl"
NODE_NOT_FOUND_WARNING = "Node.js or parse_js.js not found. Falling back to jsbeautifier. Install Node.js and Esprima (npm install esprima) or check the script path."
GITHUB_API_BASE = "https://api.github.com"
GITHUB_SEARCH_RATE_LIMIT = 30
GITHUB_CACHE: Dict[str, List[Tuple[str, str]]] = {}
s3_status_cache: Dict[str, Dict[str, str]] = {}
DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlist.txt")

# Common bucket prefixes
COMMON_BUCKET_PREFIXES = [
    "dev", "prod", "test", "staging", "backup", "data", "files", "public", "private", "logs"
]

# Regex for endpoints
regex = re.compile(
    r"""
    (?:"|')(
        # Match full URLs with /api/ or relative paths with /api/
        ((https?://example\.com)?/api/[a-zA-Z0-9_\-/]+(?:\?[a-zA-Z0-9_\-&=]*)?) |
        # Optionally include other API-like prefixes (e.g., /rest/, /v1/)
        ((https?://example\.com)?/(rest|v[0-9]+|graphql)/[a-zA-Z0-9_\-/]+(?:\?[a-zA-Z0-9_\-&=]*)?)
    )(?:"|')
    (?!\.(css|js|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot))  # Exclude static assets
    """,
    re.VERBOSE | re.IGNORECASE,
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
def load_config() -> Dict:
    """Load configuration from config.json."""
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

def save_config(config: Dict) -> None:
    """Save configuration to config.json."""
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        logging.error(f"Failed to save config: {str(e)}")

def load_cache() -> None:
    """Load GitHub cache from disk."""
    global GITHUB_CACHE
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, "rb") as f:
                GITHUB_CACHE = pickle.load(f)
    except Exception as e:
        logging.error(f"Failed to load cache: {str(e)}")

def save_cache() -> None:
    """Save GitHub cache to disk."""
    try:
        with open(CACHE_FILE, "wb") as f:
            pickle.dump(GITHUB_CACHE, f)
    except Exception as e:
        logging.error(f"Failed to save cache: {str(e)}")

# Sitemap parsing
def parse_sitemap(base_url: str) -> List[str]:
    """Fetch and parse sitemap URLs, handling sitemap indexes."""
    sitemap_urls = []
    try:
        sitemap_url = urljoin(base_url, "/sitemap.xml")
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        response = requests.get(sitemap_url, headers=headers, timeout=10)
        response.raise_for_status()

        try:
            root = ET.fromstring(response.text)
            ns = {"sitemap": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            for loc in root.findall(".//sitemap:loc", ns):
                url = loc.text.strip()
                if url:
                    sitemap_urls.append(url)
                    # Handle sitemap index by recursively parsing
                    if url.endswith(".xml"):
                        sitemap_urls.extend(parse_sitemap(url))
            logging.info(f"Found {len(sitemap_urls)} URLs in sitemap: {sitemap_url}")
        except ET.ParseError:
            try:
                soup = BeautifulSoup(response.text, "xml")
                for loc in soup.find_all("loc"):
                    url = loc.text.strip()
                    if url:
                        sitemap_urls.append(url)
                        if url.endswith(".xml"):
                            sitemap_urls.extend(parse_sitemap(url))
                logging.info(f"Fallback to lxml: Found {len(sitemap_urls)} URLs in sitemap: {sitemap_url}")
            except Exception as e:
                logging.error(f"Failed to parse sitemap XML with lxml: {str(e)}")
    except requests.RequestException as e:
        logging.warning(f"Failed to fetch sitemap {sitemap_url}: {str(e)}")
    return sitemap_urls

# Fetch URL content
def fetch_url_content(url: str, respect_robots: bool = True) -> Tuple[Optional[str], str]:
    """Fetch content from a URL, respecting robots.txt if enabled."""
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

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

# Extract JS from HTML
def extract_js_from_html(html_content: str, base_url: str = "", extract_urls: bool = False) -> List[str]:
    """Extract JavaScript code or URLs from HTML, including potential JS files."""
    js_blocks = []
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        # Extract inline scripts
        for script in soup.find_all("script", src=False):
            if script.string:
                beautified = jsbeautifier.beautify(script.string.strip())
                if beautified:
                    js_blocks.append(beautified)
        # Extract linked scripts and other potential JS files
        if extract_urls:
            for script in soup.find_all("script", src=True):
                src = script.get("src")
                if src:
                    absolute_url = urljoin(base_url, src)
                    if absolute_url.endswith(".js"):
                        js_blocks.append(absolute_url)
            # Extract links to potential JS files from <a> tags and other sources
            for link in soup.find_all("a", href=True):
                href = link.get("href")
                if href and href.endswith(".js"):
                    absolute_url = urljoin(base_url, href)
                    js_blocks.append(absolute_url)
    except Exception as e:
        logging.error(f"Error extracting JS from HTML: {str(e)}")
    return js_blocks

# Filter JS files
def filter_js_files(js_urls: List[str], pattern: str) -> List[str]:
    """Filter JavaScript URLs based on a pattern."""
    if not pattern:
        return js_urls
    return [url for url in js_urls if fnmatch.fnmatch(url, pattern)]

# Run LinkFinder
def run_linkfinder(input_path: str) -> List[str]:
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

# Extract endpoints
def extract_endpoints(content: str, file_ext: str = "") -> List[str]:
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

# Test S3 public access
def test_s3_public_access(bucket_url: str, bucket_name: str) -> Dict[str, str]:
    """Test if an S3 bucket is publicly accessible."""
    if bucket_url in s3_status_cache:
        return s3_status_cache[bucket_url]

    access = {"listing": "Not Listable", "readable": "Not Readable", "details": ""}
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
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

# Export functions
def export_s3_results(s3_buckets: List[Tuple[str, str]]) -> None:
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

def export_all_results(input_val: str, endpoints: List[str], s3_buckets: List[Tuple[str, str]], js_endpoints: Dict[str, List[str]]) -> None:
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

def export_js_endpoints(js_endpoints: Dict[str, List[str]]) -> None:
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

def run_esprima_parser(js_file_path: str, node_script_path: str) -> List[str]:
    """Run the Node.js Esprima parser script on a JavaScript file."""
    endpoints = []
    try:
        if not os.path.exists(node_script_path):
            logging.error(f"Node.js script not found at {node_script_path}")
            return endpoints
        if not os.path.exists(js_file_path):
            logging.error(f"JavaScript file not found at {js_file_path}")
            return endpoints

        cmd = ["node", node_script_path, js_file_path]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',  # Explicitly use UTF-8
            errors='replace',  # Replace invalid characters
            check=True,
            timeout=30
        )
        output = result.stdout.strip()
        endpoints = [line for line in output.splitlines() if line.strip() and line.startswith("http")]
        logging.info(f"Esprima parser processed {js_file_path}, found {len(endpoints)} endpoints")
    except subprocess.CalledProcessError as e:
        if "MODULE_NOT_FOUND" in e.stderr:
            logging.error(f"Esprima module not found. Run 'npm install esprima' in {os.path.dirname(node_script_path)}")
        else:
            logging.error(f"Esprima subprocess failed for {js_file_path}: {e.stderr}")
        logging.debug(f"Esprima stdout: {e.stdout}")
    except UnicodeDecodeError as e:
        logging.error(f"Unicode decode error in Esprima output for {js_file_path}: {str(e)}")
        logging.debug(f"Attempting to read raw output as bytes")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=False,  # Read as bytes
                check=True,
                timeout=30
            )
            output = result.stdout.decode('utf-8', errors='replace').strip()
            endpoints = [line for line in output.splitlines() if line.strip() and line.startswith("http")]
            logging.info(f"Esprima parser (bytes fallback) processed {js_file_path}, found {len(endpoints)} endpoints")
        except Exception as e2:
            logging.error(f"Bytes fallback failed for {js_file_path}: {str(e2)}")
    except subprocess.TimeoutExpired:
        logging.error(f"Esprima subprocess timed out for {js_file_path}")
    except Exception as e:
        logging.error(f"Esprima processing error for {js_file_path}: {str(e)}")
    return endpoints

def export_html_report(input_val: str, endpoints: List[str], s3_buckets: List[Tuple[str, str]], js_endpoints: Dict[str, List[str]]) -> None:
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

# Browse functions
def on_browse(entry: tk.Entry) -> None:
    """Browse for input file."""
    path = filedialog.askopenfilename(
        filetypes=[("All Files", "*.*"), ("JavaScript Files", "*.js"), ("HTML Files", "*.html")]
    )
    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)

def on_browse_linkfinder(entry: tk.Entry) -> None:
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

def on_browse_node_script(entry: tk.Entry) -> None:
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

# Subdomain discovery functions
async def async_dns_resolve(subdomain: str) -> Optional[str]:
    """Asynchronously resolve a subdomain to an IP."""
    resolver = aiodns.DNSResolver()
    try:
        result = await resolver.query(subdomain, 'A')
        return result[0].host if result else None
    except Exception:
        return None

def dns_bruteforce(domain: str, wordlist: str) -> List[str]:
    """Bruteforce subdomains using a wordlist."""
    if not wordlist or not os.path.exists(wordlist):
        wordlist = DEFAULT_WORDLIST
        if not os.path.exists(wordlist):
            logging.warning("No wordlist provided; creating default wordlist.")
            with open(wordlist, "w", encoding="utf-8") as f:
                f.write("\n".join(["admin", "api", "dev", "staging", "test"]))
    
    subdomains = []
    try:
        with open(wordlist, "r", encoding="utf-8") as f:
            words = [line.strip() for line in f if line.strip()]
        
        async def resolve_batch(batch: List[str]) -> List[str]:
            async with aiohttp.ClientSession() as session:
                tasks = [async_dns_resolve(f"{word}.{domain}") for word in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                return [f"{word}.{domain}" for word, ip in zip(batch, results) if ip]
        
        batch_size = 50
        for i in range(0, len(words), batch_size):
            batch = words[i:i + batch_size]
            loop = asyncio.get_event_loop()
            found = loop.run_until_complete(resolve_batch(batch))
            subdomains.extend(found)
            logging.info(f"Bruteforced {len(found)} subdomains in batch {i//batch_size + 1}")
    
    except Exception as e:
        logging.error(f"Bruteforce failed: {str(e)}")
    
    return subdomains

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def query_certificate_transparency(domain: str) -> List[str]:
    """Query Certificate Transparency logs for subdomains."""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        for entry in data:
            name_value = entry.get('name_value', '')
            if name_value:
                if '*.' in name_value:
                    name_value = name_value.replace('*.', '')
                if domain in name_value:
                    subdomains.add(name_value.lower())
        logging.info(f"Found {len(subdomains)} subdomains via CT logs")
    except Exception as e:
        logging.error(f"CT log query failed: {str(e)}")
        raise
    return list(subdomains)

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def query_dns_dbs(domain: str) -> List[str]:
    """Query various DNS databases for subdomains."""
    sources = [
        f"https://api.hackertarget.com/hostsearch/?q={domain}",
        f"https://riddler.io/search/exportcsv?q=pld:{domain}"
    ]
    subdomains = set()
    
    for source in sources:
        try:
            response = requests.get(source, timeout=15)
            response.raise_for_status()
            lines = response.text.splitlines()
            for line in lines:
                if ',' in line:
                    subdomain = line.split(',')[0].strip()
                else:
                    subdomain = line.strip()
                if subdomain.endswith(f".{domain}"):
                    subdomains.add(subdomain.lower())
        except Exception as e:
            logging.warning(f"Failed to query {source}: {str(e)}")
    
    logging.info(f"Found {len(subdomains)} subdomains via DNS databases")
    return list(subdomains)

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def query_securitytrails(domain: str, api_key: str) -> List[str]:
    """Query SecurityTrails API for subdomains."""
    if not api_key:
        logging.warning("SecurityTrails API key not provided")
        return []
        
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key}
    subdomains = set()
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        for subdomain in data.get('subdomains', []):
            full_domain = f"{subdomain}.{domain}"
            subdomains.add(full_domain.lower())
        logging.info(f"Found {len(subdomains)} subdomains via SecurityTrails")
    except Exception as e:
        logging.error(f"SecurityTrails API query failed: {str(e)}")
        raise
    
    return list(subdomains)

def attempt_zone_transfer(domain: str) -> List[str]:
    """Attempt DNS zone transfer with timeout."""
    subdomains = set()
    
    try:
        answers = dns.resolver.resolve(domain, 'NS', lifetime=5)
        nameservers = [str(rdata.target).rstrip('.') for rdata in answers]
        
        for ns in nameservers:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
                names = z.nodes.keys()
                for name in names:
                    subdomain = name.to_text() + '.' + domain
                    if subdomain.startswith('@'):
                        subdomain = subdomain.replace('@.', '')
                    subdomains.add(subdomain)
                logging.info(f"Successful zone transfer from {ns}!")
            except Exception as e:
                logging.debug(f"Zone transfer failed from {ns}: {str(e)}")
    except Exception as e:
        logging.error(f"Error in zone transfer attempt: {str(e)}")
    
    return list(subdomains)

def create_subdomain_tab(notebook: ttk.Notebook, main_entry: tk.Entry) -> ttk.Frame:
    # ── 1) SETUP FRAME ─────────────────────────────────────────
    subdomain_frame = ttk.Frame(notebook)
    notebook.add(subdomain_frame, text="Subdomain Discovery")

    # Define BooleanVars for discovery methods
    ct_logs_var = tk.BooleanVar(value=True)
    bruteforce_var = tk.BooleanVar(value=False)
    dns_dbs_var = tk.BooleanVar(value=True)
    securitytrails_var = tk.BooleanVar(value=False)
    zone_transfer_var = tk.BooleanVar(value=False)


    # ── 2) DEFINE CALLBACKS ───────────────────────────────────
    def validate_domain(domain: str) -> bool:
        return bool(re.match(
            r'^[a-zA-Z0-9][a-zA-Z0-9.-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$',
            domain)
        )

    def on_discover():
        domain = domain_entry.get().strip()
        if not validate_domain(domain):
            messagebox.showerror("Error", "Please enter a valid domain (e.g. example.com)")
            return

        # clear & header
        subdomain_output.delete("1.0", tk.END)
        subdomain_output.insert(tk.END, f"Discovering subdomains for {domain}...\n\n")
        subdomain_output.see(tk.END) # Scroll to the end

        discovered = set()
        wordlist_path = wordlist_entry.get().strip() or DEFAULT_WORDLIST # Get wordlist path
        securitytrails_api_key = securitytrails_api_key_entry.get().strip() # Get SecurityTrails API Key


def worker(root):
    # Function to safely update the GUI from the worker thread
    def update_output(message):
        subdomain_output.insert(tk.END, message)
        subdomain_output.see(tk.END)

    if ct_logs_var.get():
        root.after(0, update_output, "Querying Certificate Transparency logs...\n")
        try:
            ct_subs = query_certificate_transparency(domain)
            discovered.update(ct_subs)
            root.after(0, update_output, f"Found {len(ct_subs)} subdomains via CT logs.\n")
        except Exception as e:
            root.after(0, update_output, f"Error querying CT logs: {str(e)}\n")

    if bruteforce_var.get():
        root.after(0, update_output, f"Starting DNS bruteforce with {wordlist_path}...\n")
        try:
            brute_subs = dns_bruteforce(domain, wordlist_path)
            discovered.update(brute_subs)
            root.after(0, update_output, f"Found {len(brute_subs)} subdomains via bruteforce.\n")
        except Exception as e:
            root.after(0, update_output, f"Error during bruteforce: {str(e)}\n")

    if dns_dbs_var.get():
        root.after(0, update_output, "Querying DNS databases...\n")
        try:
            db_subs = query_dns_dbs(domain)
            discovered.update(db_subs)
            root.after(0, update_output, f"Found {len(db_subs)} subdomains via DNS databases.\n")
        except Exception as e:
            root.after(0, update_output, f"Error querying DNS databases: {str(e)}\n")

    if securitytrails_var.get():
        if securitytrails_api_key:
            root.after(0, update_output, "Querying SecurityTrails...\n")
            try:
                st_subs = query_securitytrails(domain, securitytrails_api_key)
                discovered.update(st_subs)
                root.after(0, update_output, f"Found {len(st_subs)} subdomains via SecurityTrails.\n")
            except Exception as e:
                root.after(0, update_output, f"Error querying SecurityTrails: {str(e)}\n")
        else:
            root.after(0, update_output, "Skipping SecurityTrails query: API key not provided.\n")

    if zone_transfer_var.get():
        root.after(0, update_output, "Attempting DNS zone transfer...\n")
        try:
            zt_subs = attempt_zone_transfer(domain)
            discovered.update(zt_subs)
            root.after(0, update_output, f"Found {len(zt_subs)} subdomains via zone transfer.\n")
        except Exception as e:
            root.after(0, update_output, f"Error during zone transfer attempt: {str(e)}\n")

    results = sorted(list(discovered))

    # display results in the main output area
    root.after(0, subdomain_output.insert, tk.END, "\n=== Complete ===\n")
    root.after(0, subdomain_output.insert, tk.END, f"Total unique subdomains found: {len(results)}\n")
    root.after(0, subdomain_output.insert, tk.END, "\n".join(results) + "\n")
    root.after(0, subdomain_output.see, tk.END)

    # enable the other buttons (update in the main thread)
    root.after(0, lambda: export_btn.config(state=tk.NORMAL))
    root.after(0, lambda: analyze_btn.config(state=tk.NORMAL))
    root.after(0, lambda: search_btn.config(state=tk.NORMAL))
    search_btn.data = results # Store results for searching and exporting (can be done in worker thread)


    def on_search(event=None):
        all_subs = getattr(search_btn, "data", [])
        if not all_subs:
            return

        q = search_entry.get().strip().lower()
        if not q:
            filtered = all_subs
        else:
            filtered = [s for s in all_subs if q in s.lower()]

        # Clear and display filtered results
        subdomain_output.delete("1.0", tk.END)
        if filtered:
            subdomain_output.insert(tk.END, f"Found {len(filtered)} matching subdomains:\n\n")
            subdomain_output.insert(tk.END, "\n".join(filtered) + "\n")
        else:
            subdomain_output.insert(tk.END, "No matching subdomains found.\n")
        subdomain_output.see(tk.END)


    def export_subdomains():
        subs = getattr(search_btn, "data", [])
        if not subs:
            messagebox.showinfo("Export", "No subdomains to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(subs))
            messagebox.showinfo("Export", f"Saved to {path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export subdomains: {str(e)}")


    def analyze_subdomains():
        subs = getattr(search_btn, "data", [])
        if not subs:
            messagebox.showinfo("Analyze", "No subdomains to analyze.")
            return
        # Placeholder for liveness checks or other analysis
        messagebox.showinfo("Analyze", f"Analyzing {len(subs)} subdomains (Analysis not fully implemented).")


    def integrate_with_main():
        subs = getattr(search_btn, "data", [])
        if not subs:
            messagebox.showinfo("Integrate", "No subdomains to send.")
            return
        # Example: pick the first subdomain and insert into the main tab’s entry:
        if subs:
            main_entry.delete(0, tk.END)
            # Prepend https:// for consistency if it's a URL input field
            main_entry.insert(0, f"https://{subs[0]}")
            notebook.select(0)  # switch back to main tab
        else:
             messagebox.showinfo("Integrate", "No subdomains to send.")


    # ── 3) DOMAIN ENTRY AND OPTIONS ────────────────────────────
    domain_frame = ttk.Frame(subdomain_frame)
    domain_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(domain_frame, text="Target Domain:").pack(side=tk.LEFT)
    domain_entry = ttk.Entry(domain_frame, width=40)
    domain_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

    # Add SecurityTrails API Key Entry
    securitytrails_frame = ttk.Frame(subdomain_frame)
    securitytrails_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(securitytrails_frame, text="SecurityTrails API Key:").pack(side=tk.LEFT)
    securitytrails_api_key_entry = ttk.Entry(securitytrails_frame, width=40, show="*")
    securitytrails_api_key_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
     # Optional: Load API key from config if you add it there

    # Add Wordlist Entry
    wordlist_frame = ttk.Frame(subdomain_frame)
    wordlist_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(wordlist_frame, text="Wordlist Path (for bruteforce):").pack(side=tk.LEFT)
    wordlist_entry = ttk.Entry(wordlist_frame, width=40)
    wordlist_entry.insert(0, DEFAULT_WORDLIST) # Default path
    wordlist_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
    ttk.Button(wordlist_frame, text="Browse", command=lambda: on_browse(wordlist_entry)).pack(side=tk.LEFT)


    # Add Checkboxes for Discovery Methods
    methods_frame = ttk.Frame(subdomain_frame)
    methods_frame.pack(fill=tk.X, padx=10, pady=5)

    ttk.Checkbutton(methods_frame, text="Certificate Transparency Logs (crt.sh)", variable=ct_logs_var).pack(side=tk.LEFT, padx=5)
    ttk.Checkbutton(methods_frame, text="DNS Bruteforce", variable=bruteforce_var).pack(side=tk.LEFT, padx=5)
    ttk.Checkbutton(methods_frame, text="DNS Databases (hackertarget, riddler)", variable=dns_dbs_var).pack(side=tk.LEFT, padx=5)
    ttk.Checkbutton(methods_frame, text="SecurityTrails API (requires API key)", variable=securitytrails_var).pack(side=tk.LEFT, padx=5)
    ttk.Checkbutton(methods_frame, text="DNS Zone Transfer Attempt", variable=zone_transfer_var).pack(side=tk.LEFT, padx=5)


    # ── 4) SEARCH ROW ─────────────────────────────────────────
    search_frame = ttk.Frame(subdomain_frame)
    search_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(search_frame, text="Filter Results:").pack(side=tk.LEFT)
    search_entry = ttk.Entry(search_frame, width=40)
    search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
    search_btn = ttk.Button(search_frame, text="Filter", state=tk.DISABLED, command=on_search)
    search_btn.pack(side=tk.LEFT)
    search_entry.bind("<Return>", on_search)

    # ── 5) OUTPUT AREA ────────────────────────────────────────
    subdomain_output = scrolledtext.ScrolledText(
        subdomain_frame, wrap=tk.WORD, width=80, height=15
    )
    subdomain_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    # ── 6) BOTTOM BUTTON BAR ──────────────────────────────────
    button_frame = ttk.Frame(subdomain_frame)
    button_frame.pack(fill=tk.X, padx=10, pady=5)

    discover_btn  = ttk.Button(button_frame, text="Discover Subdomains", command=on_discover)
    export_btn    = ttk.Button(button_frame, text="Export Results",   state=tk.DISABLED, command=export_subdomains)
    analyze_btn   = ttk.Button(button_frame, text="Analyze Live (Not Implemented)",  state=tk.DISABLED, command=analyze_subdomains) # Renamed for clarity
    integrate_btn = ttk.Button(button_frame, text="Send First to Main Tool", command=integrate_with_main) # Renamed for clarity

    for btn in (discover_btn, export_btn, analyze_btn, integrate_btn):
        btn.pack(side=tk.LEFT, padx=5)

    return subdomain_frame

# Generate bucket names
def generate_bucket_names(target: str) -> List[str]:
    """Generate potential S3 bucket names based on target, if enabled."""
    bucket_names = []
    parsed = urlparse(target) if target.startswith("http") else None
    base_name = parsed.netloc.split('.')[0] if parsed else os.path.splitext(os.path.basename(target))[0]
    for prefix in COMMON_BUCKET_PREFIXES + [""]:
        for suffix in COMMON_BUCKET_PREFIXES + [""]:
            if prefix or suffix:
                name = f"{prefix}{base_name}{suffix}".strip("-")
                bucket_names.append(name)
    logging.debug(f"Generated {len(bucket_names)} potential bucket names for {target}")
    return sorted(set(bucket_names))

def validate_bucket_name(bucket_name: str) -> bool:
    """Validate an S3 bucket name according to AWS naming rules."""
    if not (3 <= len(bucket_name) <= 63):
        return False
    # Must be lowercase letters, numbers, dots, or hyphens
    if not re.match(r'^[a-z0-9.-]+$', bucket_name):
        return False
    # Must not start or end with a hyphen or dot
    if bucket_name.startswith(('-', '.')) or bucket_name.endswith(('-', '.')):
        return False
    # Must not contain consecutive dots or dot-hyphen combinations
    if '..' in bucket_name or '.-' in bucket_name or '-.' in bucket_name:
        return False
    # Must not be an IP address format
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', bucket_name):
        return False
    return True

# Extract S3 buckets (modified to respect generate_buckets flag)
def extract_s3_buckets(
    endpoints: List[str],
    target: str = "",
    github_pat: str = "",
    use_github_search: bool = False,
    generate_buckets: bool = False
) -> List[Tuple[str, str]]:
    """Extract S3 buckets from endpoints, with optional bucket generation."""
    s3_buckets = []
    seen_names = set()
    
    # Extract S3 buckets directly from endpoints
    for endpoint in endpoints:
        matches = s3_regex.findall(endpoint)
        for match in matches:
            bucket_name = next((m for m in match if m), None)
            if bucket_name and validate_bucket_name(bucket_name) and bucket_name not in seen_names:
                s3_buckets.append((bucket_name, endpoint))
                seen_names.add(bucket_name)
                logging.debug(f"Found S3 bucket in endpoint: {bucket_name} ({endpoint})")
    
    # Generate additional bucket names only if enabled
    if generate_buckets:
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
                    logging.debug(f"Generated S3 bucket: {name} ({url_format})")
    
    # Include GitHub search results if enabled
    if use_github_search and github_pat:
        github_buckets = search_github_for_buckets(target, github_pat)
        for bucket_name, bucket_url in github_buckets:
            if bucket_name not in seen_names:
                s3_buckets.append((bucket_name, bucket_url))
                seen_names.add(bucket_name)
                logging.debug(f"Found S3 bucket via GitHub: {bucket_name} ({bucket_url})")
    
    logging.info(f"Total S3 buckets extracted: {len(s3_buckets)}")
    return sorted(s3_buckets, key=lambda x: x[0])

def send_api_request(base_url: str, endpoint_path: str, method: str, body: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> Tuple[Optional[requests.Response], str]:
    """Send an HTTP request to an endpoint and return the response."""
    full_url = urljoin(base_url, endpoint_path)
    method = method.upper()
    headers = headers or {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    
    try:
        response = requests.request(
            method=method,
            url=full_url,
            headers=headers,
            data=body if body else None,
            timeout=10
        )
        logging.info(f"Sent {method} request to {full_url}, status: {response.status_code}")
        return response, ""
    except requests.RequestException as e:
        logging.error(f"Failed to send {method} request to {full_url}: {str(e)}")
        return None, str(e)

# Analyze input (modified for clearer logging)
def analyze_input(
    input_str: str,
    include_all_linked: bool = False,
    crawl_depth: int = 0,
    use_linkfinder: bool = False,
    js_filter: str = "",
    max_pages: int = 100,
    respect_robots: bool = True,
    progress_var: Optional[tk.DoubleVar] = None,
    progress_bar: Optional[ttk.Progressbar] = None,
    github_pat: str = "",
    use_github_search: bool = False,
    use_esprima: bool = False,
    node_script_path: str = DEFAULT_NODE_SCRIPT_PATH,
    generate_buckets: bool = False,
    scan_subdirs: bool = False
) -> Tuple[List[str], List[Tuple[str, str]], Dict[str, List[str]]]:
    """Analyze input to extract endpoints and S3 buckets."""
    endpoints = []
    s3_buckets = []
    js_endpoints = {}
    
    def process_js_content(js_code: str, source: str, file_ext: str = ".js") -> List[str]:
        """Process JavaScript content with Esprima or fallback."""
        current_endpoints = []
        logging.debug(f"Processing JS content from {source} (type: {file_ext})")
        if use_esprima and file_ext == ".js":
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".js", mode='w', encoding='utf-8') as temp_js:
                    temp_js.write(js_code)
                    temp_js_path = temp_js.name
                if os.path.exists(temp_js_path) and os.path.getsize(temp_js_path) > 0:
                    logging.debug(f"Running Esprima on {temp_js_path}")
                    esprima_endpoints = run_esprima_parser(temp_js_path, node_script_path)
                    if esprima_endpoints:
                        current_endpoints.extend(esprima_endpoints)
                        js_endpoints[source] = sorted(set(esprima_endpoints))
                    else:
                        logging.warning(f"Esprima returned no endpoints for {source}; falling back to regex")
                        current_endpoints.extend(extract_endpoints(js_code, file_ext))
                        js_endpoints[source] = sorted(set(current_endpoints))
                else:
                    logging.warning(f"Temporary JS file {temp_js_path} is empty or not created; using regex")
                    current_endpoints.extend(extract_endpoints(js_code, file_ext))
                    js_endpoints[source] = sorted(set(current_endpoints))
            except Exception as e:
                logging.error(f"Esprima processing failed for {source}: {str(e)}")
                current_endpoints.extend(extract_endpoints(js_code, file_ext))
                js_endpoints[source] = sorted(set(current_endpoints))
            finally:
                if 'temp_js_path' in locals() and os.path.exists(temp_js_path):
                    try:
                        os.unlink(temp_js_path)
                        logging.debug(f"Deleted temporary JS file: {temp_js_path}")
                    except Exception as e:
                        logging.error(f"Failed to delete temporary file {temp_js_path}: {str(e)}")
        else:
            current_endpoints.extend(extract_endpoints(js_code, file_ext))
            logging.debug(f"Extracted {len(current_endpoints)} endpoints from {source} using regex")
            js_endpoints[source] = sorted(set(current_endpoints))
        
        if use_linkfinder and file_ext == ".js":
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".js", mode='w', encoding='utf-8') as temp_js:
                    temp_js.write(js_code)
                    temp_js_path = temp_js.name
                if os.path.exists(temp_js_path) and os.path.getsize(temp_js_path) > 0:
                    logging.debug(f"Running LinkFinder on {temp_js_path}")
                    lf_endpoints = run_linkfinder(temp_js_path)
                    current_endpoints.extend(lf_endpoints)
                    if source in js_endpoints:
                        js_endpoints[source].extend(lf_endpoints)
                        js_endpoints[source] = sorted(set(js_endpoints[source]))
                    else:
                        js_endpoints[source] = sorted(set(lf_endpoints))
                    logging.debug(f"LinkFinder found {len(lf_endpoints)} endpoints in {source}")
            except Exception as e:
                logging.error(f"LinkFinder processing failed for {source}: {str(e)}")
            finally:
                if 'temp_js_path' in locals() and os.path.exists(temp_js_path):
                    try:
                        os.unlink(temp_js_path)
                    except Exception as e:
                        logging.error(f"Failed to delete temporary file {temp_js_path}: {str(e)}")
        
        return current_endpoints

    logging.info(f"Analyzing input: {input_str}")
    if os.path.isfile(input_str):
        try:
            with open(input_str, "r", encoding="utf-8") as f:
                content = f.read()
            file_ext = os.path.splitext(input_str)[1].lower()
            if file_ext == ".js":
                endpoints = process_js_content(content, input_str, file_ext)
                js_endpoints[input_str] = endpoints
            elif file_ext in [".html", ".htm"]:
                js_blocks = extract_js_from_html(content)
                for i, script in enumerate(js_blocks):
                    script_endpoints = process_js_content(script, f"{input_str}:inline_{i}", ".js")
                    endpoints.extend(script_endpoints)
                    js_endpoints[f"{input_str}:inline_{i}"] = script_endpoints
            else:
                endpoints = extract_endpoints(content, file_ext)
            endpoints = sorted(set(endpoints))
            logging.info(f"Processed file {input_str}, found {len(endpoints)} endpoints")
        except Exception as e:
            logging.error(f"Failed to process file {input_str}: {str(e)}")
    elif input_str.startswith("http"):
        visited = set()
        queue = deque([(input_str, 0)])
        to_process = [(input_str, 0)]
        base_domain = urlparse(input_str).netloc
        all_js_files = []
        page_count = 0
        subdir_js_files = []

        logging.debug(f"Fetching sitemap for {input_str}")
        sitemap_urls = parse_sitemap(input_str)
        for s_url in sitemap_urls:
            if urlparse(s_url).netloc == base_domain and s_url not in visited:
                queue.append((s_url, 0))
                to_process.append((s_url, 0))
        logging.debug(f"Found {len(sitemap_urls)} sitemap URLs")

        def crawl_subdirs(base_url: str) -> List[str]:
            js_files = []
            parsed = urlparse(base_url)
            base_path = parsed.scheme + "://" + parsed.netloc
            directories = ["/js/", "/scripts/", "/assets/", "/static/"]
            for dir_path in directories:
                dir_url = urljoin(base_path, dir_path)
                try:
                    content, content_type = fetch_url_content(dir_url, respect_robots)
                    if content and "html" in content_type.lower():
                        soup = BeautifulSoup(content, "html.parser")
                        for link in soup.find_all("a", href=True):
                            href = link.get("href")
                            if href.endswith(".js"):
                                js_url = urljoin(dir_url, href)
                                if urlparse(js_url).netloc == base_domain:
                                    js_files.append(js_url)
                                    logging.debug(f"Found JS file in subdirectory: {js_url}")
                    else:
                        logging.debug(f"Directory {dir_url} is not HTML or inaccessible")
                except Exception as e:
                    logging.debug(f"Failed to crawl directory {dir_url}: {str(e)}")
            return js_files

        # Run subdirectory crawl (your snippet)
        if include_all_linked and scan_subdirs:
            subdir_js_files = crawl_subdirs(input_str)
            logging.info(f"Found {len(subdir_js_files)} JS files in subdirectories")
            for js_url in subdir_js_files:
                if js_url not in visited:
                    queue.append((js_url, 0))
                    to_process.append((js_url, 0))

        with ThreadPoolExecutor(max_workers=10) as executor:
            while queue and page_count < max_pages:
                url, depth = queue.popleft()
                if url in visited or depth > crawl_depth:
                    continue
                visited.add(url)
                page_count += 1
                logging.debug(f"Processing URL {url} (depth {depth}, page {page_count}/{max_pages})")

                future = executor.submit(fetch_url_content, url, respect_robots)
                html_content, info = future.result()
                if html_content is None:
                    logging.warning(f"Skipping {url} due to fetch failure: {info}")
                    continue

                current_endpoints = []
                file_ext = ".html" if "html" in info.lower() else ".js" if "javascript" in info.lower() else ""
                logging.debug(f"Content type for {url}: {info}")
                if file_ext == ".html":
                    js_blocks = extract_js_from_html(html_content, url, extract_urls=include_all_linked)
                    linked_sources = [s for s in js_blocks if s.startswith("http") and s.endswith(".js")]
                    inline_scripts = [s for s in js_blocks if not s.startswith("http")]
                    logging.debug(f"Found {len(linked_sources)} linked JS files and {len(inline_scripts)} inline scripts")

                    for script in inline_scripts:
                        script_endpoints = process_js_content(script, f"{url}:inline", ".js")
                        current_endpoints.extend(script_endpoints)
                        logging.debug(f"Extracted {len(script_endpoints)} endpoints from inline script")

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
                                logging.debug(f"Extracted {len(js_file_endpoints)} endpoints from {js_url}")
                else:
                    current_endpoints = process_js_content(html_content, url, file_ext)
                    all_js_files.append(url)
                    logging.debug(f"Extracted {len(current_endpoints)} endpoints from {url}")

                # Crawl linked pages if within depth
                if file_ext == ".html" and depth < crawl_depth:
                    soup = BeautifulSoup(html_content, "html.parser")
                    for link in soup.find_all("a", href=True):
                        href = urljoin(url, link.get("href"))
                        if urlparse(href).netloc == base_domain and href not in visited:
                            queue.append((href, depth + 1))
                            to_process.append((href, depth + 1))

                endpoints.extend(current_endpoints)

                if progress_var and progress_bar:
                    processed = len(visited)
                    total = len(to_process)
                    progress_var.set((processed / max(total, 1)) * 100)
                    progress_bar.update()

        endpoints = sorted(set(endpoints))
        logging.info(f"Processed {len(all_js_files)} JS files, found {len(endpoints)} total endpoints")
        s3_buckets = extract_s3_buckets(endpoints, input_str, github_pat, use_github_search, generate_buckets)

    return endpoints, s3_buckets, js_endpoints
    
def process_js_content(js_code: str, source: str, file_ext: str = ".js") -> List[str]:
    """Process JavaScript content with Esprima or fallback."""
    current_endpoints = []
    logging.debug(f"Processing JS content from {source} (type: {file_ext})")
    if use_esprima and file_ext == ".js":
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".js", mode='w', encoding='utf-8') as temp_js:
                temp_js.write(js_code)
                temp_js_path = temp_js.name
            if os.path.exists(temp_js_path) and os.path.getsize(temp_js_path) > 0:
                logging.debug(f"Running Esprima on {temp_js_path}")
                esprima_endpoints = run_esprima_parser(temp_js_path, node_script_path)
                if esprima_endpoints:
                    current_endpoints.extend(esprima_endpoints)
                    js_endpoints[source] = sorted(set(esprima_endpoints))
                else:
                    logging.warning(f"Esprima returned no endpoints for {source}; falling back to regex")
                    current_endpoints.extend(extract_endpoints(js_code, file_ext))
                    js_endpoints[source] = sorted(set(current_endpoints))
            else:
                logging.warning(f"Temporary JS file {temp_js_path} is empty or not created; using regex")
                current_endpoints.extend(extract_endpoints(js_code, file_ext))
                js_endpoints[source] = sorted(set(current_endpoints))
        except Exception as e:
            logging.error(f"Esprima processing failed for {source}: {str(e)}")
            current_endpoints.extend(extract_endpoints(js_code, file_ext))
            js_endpoints[source] = sorted(set(current_endpoints))
        finally:
            if 'temp_js_path' in locals() and os.path.exists(temp_js_path):
                try:
                    os.unlink(temp_js_path)
                    logging.debug(f"Deleted temporary JS file: {temp_js_path}")
                except Exception as e:
                    logging.error(f"Failed to delete temporary file {temp_js_path}: {str(e)}")
    else:
        current_endpoints.extend(extract_endpoints(js_code, file_ext))
        logging.debug(f"Extracted {len(current_endpoints)} endpoints from {source} using regex")
        js_endpoints[source] = sorted(set(current_endpoints))
    
    if use_linkfinder and file_ext == ".js":
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".js", mode='w', encoding='utf-8') as temp_js:
                temp_js.write(js_code)
                temp_js_path = temp_js.name
            if os.path.exists(temp_js_path) and os.path.getsize(temp_js_path) > 0:
                logging.debug(f"Running LinkFinder on {temp_js_path}")
                lf_endpoints = run_linkfinder(temp_js_path)
                current_endpoints.extend(lf_endpoints)
                if source in js_endpoints:
                    js_endpoints[source].extend(lf_endpoints)
                    js_endpoints[source] = sorted(set(js_endpoints[source]))
                else:
                    js_endpoints[source] = sorted(set(lf_endpoints))
                logging.debug(f"LinkFinder found {len(lf_endpoints)} endpoints in {source}")
        except Exception as e:
            logging.error(f"LinkFinder processing failed for {source}: {str(e)}")
        finally:
            if 'temp_js_path' in locals() and os.path.exists(temp_js_path):
                try:
                    os.unlink(temp_js_path)
                except Exception as e:
                    logging.error(f"Failed to delete temporary file {temp_js_path}: {str(e)}")
    
    return current_endpoints

# GUI (modified to add S3 bucket generation toggle)
def create_gui():
    root = tk.Tk()
    root.title("S3 Bucket and Endpoint Extractor")
    root.geometry("1800x900")

    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)

    main_frame = ttk.Frame(notebook)
    notebook.add(main_frame, text="Endpoint Discovery")

    config_frame = ttk.Frame(main_frame)
    config_frame.pack(padx=10, pady=5, fill=tk.X)

    config = load_config()
    ttk.Label(config_frame, text="LinkFinder Path:").pack(side=tk.LEFT)
    linkfinder_entry = ttk.Entry(config_frame, width=20)
    linkfinder_entry.insert(0, config.get("linkfinder_path", DEFAULT_LINKFINDER_PATH))
    linkfinder_entry.pack(side=tk.LEFT, padx=(0, 5))
    ttk.Button(config_frame, text="Browse", command=lambda: on_browse_linkfinder(linkfinder_entry)).pack(side=tk.LEFT)

    ttk.Label(config_frame, text="Node.js Script:").pack(side=tk.LEFT, padx=5)
    node_script_entry = ttk.Entry(config_frame, width=20)
    node_script_entry.insert(0, config.get("node_script_path", DEFAULT_NODE_SCRIPT_PATH))
    node_script_entry.pack(side=tk.LEFT, padx=(0, 5))
    ttk.Button(config_frame, text="Browse", command=lambda: on_browse_node_script(node_script_entry)).pack(side=tk.LEFT)

    ttk.Label(config_frame, text="GitHub PAT:").pack(side=tk.LEFT, padx=5)
    github_pat_entry = ttk.Entry(config_frame, width=20, show="*")
    github_pat_entry.insert(0, config.get("github_pat", ""))
    github_pat_entry.pack(side=tk.LEFT, padx=(0, 5))

    input_frame = ttk.Frame(main_frame)
    input_frame.pack(padx=10, pady=5, fill=tk.X)
    ttk.Label(input_frame, text="URL/File:").pack(side=tk.LEFT)
    entry = ttk.Entry(input_frame, width=50)
    entry.pack(side=tk.LEFT, padx=(0, 5), expand=True, fill=tk.X)
    ttk.Button(input_frame, text="Browse", command=lambda: on_browse(entry)).pack(side=tk.LEFT)

    crawl_frame = ttk.Frame(main_frame)
    crawl_frame.pack(padx=10, pady=5, fill=tk.X)
    ttk.Label(crawl_frame, text="Crawl Depth:").pack(side=tk.LEFT)
    depth_entry = ttk.Spinbox(crawl_frame, from_=0, to=10, width=5)
    depth_entry.pack(side=tk.LEFT, padx=5)
    ttk.Label(crawl_frame, text="Max Pages:").pack(side=tk.LEFT, padx=5)
    max_pages_entry = ttk.Spinbox(crawl_frame, from_=1, to=1000, width=5)
    max_pages_entry.delete(0, tk.END)
    max_pages_entry.insert(0, "100")
    max_pages_entry.pack(side=tk.LEFT, padx=5)
    ttk.Label(crawl_frame, text="(Depth 0 = input only; Max pages limits crawl)").pack(side=tk.LEFT)

    js_filter_frame = ttk.Frame(main_frame)
    js_filter_frame.pack(padx=10, pady=5, fill=tk.X)
    ttk.Label(js_filter_frame, text="JS File Filter (e.g., *.min.js):").pack(side=tk.LEFT)
    js_filter_entry = ttk.Entry(js_filter_frame, width=20)
    js_filter_entry.pack(side=tk.LEFT, padx=5)
    ttk.Label(js_filter_frame, text="(Leave blank for all JS files)").pack(side=tk.LEFT)

    subdir_frame = ttk.Frame(main_frame)
    subdir_frame.pack(padx=10, pady=5, fill=tk.X)
    scan_subdirs_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        subdir_frame,
        text="Scan subdirectories for JS files",
        variable=scan_subdirs_var
    ).pack(side=tk.LEFT, padx=5)

    subdomain_tab = create_subdomain_tab(notebook, entry, root)

    results_tab = ttk.Frame(notebook)
    notebook.add(results_tab, text="Consolidated Results")
    results_output = scrolledtext.ScrolledText(results_tab, wrap=tk.WORD, width=80, height=20)
    results_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Add Endpoint Tester Tab
    tester_frame = ttk.Frame(notebook)
    notebook.add(tester_frame, text="Endpoint Tester")

    # Base URL
    base_url_frame = ttk.Frame(tester_frame)
    base_url_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(base_url_frame, text="Base URL:").pack(side=tk.LEFT)
    base_url_entry = ttk.Entry(base_url_frame, width=50)
    base_url_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

    # Endpoint Path
    endpoint_frame = ttk.Frame(tester_frame)
    endpoint_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(endpoint_frame, text="Endpoint Path:").pack(side=tk.LEFT)
    endpoint_entry = ttk.Entry(endpoint_frame, width=50)
    endpoint_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

    # HTTP Method
    method_frame = ttk.Frame(tester_frame)
    method_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(method_frame, text="HTTP Method:").pack(side=tk.LEFT)
    method_var = tk.StringVar(value="GET")
    methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
    method_menu = ttk.OptionMenu(method_frame, method_var, "GET", *methods)
    method_menu.pack(side=tk.LEFT, padx=5)

    # Headers
    headers_frame = ttk.Frame(tester_frame)
    headers_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(headers_frame, text="Headers (JSON):").pack(side=tk.LEFT)
    headers_text = scrolledtext.ScrolledText(headers_frame, wrap=tk.WORD, width=50, height=5)
    headers_text.pack(fill=tk.X, padx=5, pady=5)
    headers_text.insert(tk.END, '{\n  "Content-Type": "application/json"\n}')

    # Request Body
    body_frame = ttk.Frame(tester_frame)
    body_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(body_frame, text="Request Body:").pack(side=tk.LEFT)
    body_text = scrolledtext.ScrolledText(body_frame, wrap=tk.WORD, width=50, height=5)
    body_text.pack(fill=tk.X, padx=5, pady=5)

    # Send Button
    send_frame = ttk.Frame(tester_frame)
    send_frame.pack(fill=tk.X, padx=10, pady=5)
    send_btn = ttk.Button(send_frame, text="Send Request", command=lambda: on_send_request())
    send_btn.pack(side=tk.LEFT, padx=5)

    # Response Output
    response_output = scrolledtext.ScrolledText(tester_frame, wrap=tk.WORD, width=100, height=20)
    response_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    options_frame = ttk.Frame(main_frame)
    options_frame.pack(padx=10, pady=5, fill=tk.X)
    linkfinder_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        options_frame,
        text="Use LinkFinder for JS endpoint extraction",
        variable=linkfinder_var
    ).pack(side=tk.LEFT, padx=5)
    respect_robots_var = tk.BooleanVar(value=config.get("respect_robots", True))
    ttk.Checkbutton(
        options_frame,
        text="Respect robots.txt (recommended for ethical crawling)",
        variable=respect_robots_var
    ).pack(side=tk.LEFT, padx=5)
    use_github_search_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        options_frame,
        text="Search GitHub for S3 buckets (requires PAT, use ethically)",
        variable=use_github_search_var
    ).pack(side=tk.LEFT, padx=5)
    use_esprima_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        options_frame,
        text="Use Esprima for advanced JS parsing (requires Node.js)",
        variable=use_esprima_var
    ).pack(side=tk.LEFT, padx=5)
    generate_buckets_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        options_frame,
        text="Generate potential S3 bucket names (may produce unrelated results)",
        variable=generate_buckets_var
    ).pack(side=tk.LEFT, padx=5)

    def on_extract(entry, output_area, progress_var, progress_bar, depth_entry, linkfinder_var, js_filter_entry, max_pages_entry, respect_robots_var, include_all_linked=False, scan_subdirs=False):
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
        generate_buckets = generate_buckets_var.get()

        def extraction_task():
            output_area.delete(1.0, tk.END)
            output_area.insert(tk.END, f"Analyzing {input_val}...\n\n")
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
                node_script_path=node_script_path,
                generate_buckets=generate_buckets,
                scan_subdirs=scan_subdirs
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

            results_output.delete(1.0, tk.END)
            results_output.insert(tk.END, f"Results for {input_val}\n\n")
            results_output.insert(tk.END, output_area.get(1.0, tk.END))

            export_s3_btn.data = s3_buckets
            export_all_btn.data = (input_val, endpoints, s3_buckets, js_endpoints)
            export_js_btn.data = js_endpoints
            export_html_btn.data = (input_val, endpoints, s3_buckets, js_endpoints)
            # Store endpoints for tester tab
            send_btn.endpoints = endpoints
            send_btn.js_endpoints = js_endpoints

            export_s3_btn.config(state=tk.NORMAL if s3_buckets else tk.DISABLED)
            export_all_btn.config(state=tk.NORMAL if endpoints or s3_buckets or js_endpoints else tk.DISABLED)
            export_js_btn.config(state=tk.NORMAL if js_endpoints else tk.DISABLED)
            export_html_btn.config(state=tk.NORMAL if endpoints or s3_buckets or js_endpoints else tk.DISABLED)

            progress_var.set(0)
            progress_bar.update()

        threading.Thread(target=extraction_task, daemon=True).start()

    def on_scan_subdirs():
        input_val = entry.get().strip()
        if not input_val:
            messagebox.showerror("Error", "Please enter a URL or file path.")
            return
        on_extract(entry, output_area, progress_var, progress_bar, depth_entry, linkfinder_var, js_filter_entry, max_pages_entry, respect_robots_var, include_all_linked=True, scan_subdirs=True)

    def on_send_request():
        base_url = base_url_entry.get().strip()
        endpoint_path = endpoint_entry.get().strip()
        method = method_var.get()
        body = body_text.get("1.0", tk.END).strip()
        headers_text_content = headers_text.get("1.0", tk.END).strip()

        if not base_url or not endpoint_path:
            messagebox.showerror("Error", "Please enter both Base URL and Endpoint Path.")
            return

        try:
            headers = json.loads(headers_text_content) if headers_text_content else {}
        except json.JSONDecodeError as e:
            messagebox.showerror("Error", f"Invalid JSON headers: {str(e)}")
            return

        def send_task():
            response, error = send_api_request(base_url, endpoint_path, method, body, headers)
            root.after(0, update_response, response, error)

        def update_response(response, error):
            response_output.delete("1.0", tk.END)
            if error:
                response_output.insert(tk.END, f"Error: {error}\n")
                return
            response_output.insert(tk.END, f"Status: {response.status_code} {response.reason}\n")
            response_output.insert(tk.END, "\nHeaders:\n")
            for key, value in response.headers.items():
                response_output.insert(tk.END, f"{key}: {value}\n")
            response_output.insert(tk.END, "\nBody:\n")
            try:
                json_body = response.json()
                response_output.insert(tk.END, json.dumps(json_body, indent=2))
            except ValueError:
                response_output.insert(tk.END, response.text)
            response_output.see(tk.END)

        threading.Thread(target=send_task, daemon=True).start()

    button_frame = ttk.Frame(main_frame)
    button_frame.pack(pady=5)
    export_s3_btn = ttk.Button(button_frame, text="Export S3 Results", state=tk.DISABLED,
                              command=lambda: export_s3_results(getattr(export_s3_btn, 'data', [])))
    export_all_btn = ttk.Button(
        button_frame,
        text="Export JSON",
        state=tk.DISABLED,
        command=lambda: export_all_results(*getattr(export_all_btn, 'data', ('', [], [], {})))
    )
    export_js_btn = ttk.Button(
        button_frame,
        text="Export JS Endpoints",
        state=tk.DISABLED,
        command=lambda: export_js_endpoints(getattr(export_js_btn, 'data', {})))
    export_html_btn = ttk.Button(
        button_frame,
        text="Export HTML Report",
        state=tk.DISABLED,
        command=lambda: export_html_report(*getattr(export_html_btn, 'data', ('', [], [], {})))
    )
    extract_btn = ttk.Button(
        button_frame,
        text="Extract Inline",
        command=lambda: on_extract(entry, output_area, progress_var, progress_bar, depth_entry, linkfinder_var, js_filter_entry, max_pages_entry, respect_robots_var, False)
    )
    extract_all_btn = ttk.Button(
        button_frame,
        text="Extract All JS (linked too)",
        command=lambda: on_extract(entry, output_area, progress_var, progress_bar, depth_entry, linkfinder_var, js_filter_entry, max_pages_entry, respect_robots_var, True)
    )
    scan_subdirs_btn = ttk.Button(
        button_frame,
        text="Scan Subdirectories",
        command=on_scan_subdirs
    )
    extract_btn.pack(side=tk.LEFT, padx=5)
    extract_all_btn.pack(side=tk.LEFT, padx=5)
    scan_subdirs_btn.pack(side=tk.LEFT, padx=5)
    export_s3_btn.pack(side=tk.LEFT, padx=5)
    export_all_btn.pack(side=tk.LEFT, padx=5)
    export_js_btn.pack(side=tk.LEFT, padx=5)
    export_html_btn.pack(side=tk.LEFT, padx=5)

    progress_var = tk.DoubleVar()
    progress_bar = ttk.Progressbar(main_frame, variable=progress_var, maximum=100)
    progress_bar.pack(fill=tk.X, padx=10, pady=5)

    output_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=100, height=25)
    output_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    load_cache()
    root.mainloop()


def create_subdomain_tab(notebook: ttk.Notebook, main_entry: tk.Entry, root: tk.Tk) -> ttk.Frame:
    # ── 1) SETUP FRAME ─────────────────────────────────────────
    subdomain_frame = ttk.Frame(notebook)
    notebook.add(subdomain_frame, text="Subdomain Discovery")

    # Define BooleanVars for discovery methods
    ct_logs_var = tk.BooleanVar(value=True)
    bruteforce_var = tk.BooleanVar(value=False)
    dns_dbs_var = tk.BooleanVar(value=True)
    securitytrails_var = tk.BooleanVar(value=False)
    zone_transfer_var = tk.BooleanVar(value=False)


    # ── 2) DEFINE CALLBACKS ───────────────────────────────────
    def validate_domain(domain: str) -> bool:
        return bool(re.match(
            r'^[a-zA-Z0-9][a-zA-Z0-9.-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$',
            domain)
        )

    def on_discover():
        domain = domain_entry.get().strip()
        if not validate_domain(domain):
            messagebox.showerror("Error", "Please enter a valid domain (e.g. example.com)")
            return

        # clear & header
        subdomain_output.delete("1.0", tk.END)
        subdomain_output.insert(tk.END, f"Discovering subdomains for {domain}...\n\n")
        subdomain_output.see(tk.END) # Scroll to the end

        discovered = set()
        wordlist_path = wordlist_entry.get().strip() or DEFAULT_WORDLIST # Get wordlist path
        securitytrails_api_key = securitytrails_api_key_entry.get().strip() # Get SecurityTrails API Key


        def worker(root):
            # Function to safely update the GUI from the worker thread
            def update_output(message):
                subdomain_output.insert(tk.END, message)
                subdomain_output.see(tk.END)

            if ct_logs_var.get():
                root.after(0, update_output, "Querying Certificate Transparency logs...\n")
                try:
                    ct_subs = query_certificate_transparency(domain)
                    discovered.update(ct_subs)
                    root.after(0, update_output, f"Found {len(ct_subs)} subdomains via CT logs.\n")
                except Exception as e:
                    root.after(0, update_output, f"Error querying CT logs: {str(e)}\n")


            if bruteforce_var.get():
                root.after(0, update_output, f"Starting DNS bruteforce with {wordlist_path}...\n")
                try:
                    brute_subs = dns_bruteforce(domain, wordlist_path)
                    discovered.update(brute_subs)
                    root.after(0, update_output, f"Found {len(brute_subs)} subdomains via bruteforce.\n")
                except Exception as e:
                    root.after(0, update_output, f"Error during bruteforce: {str(e)}\n")


            if dns_dbs_var.get():
                root.after(0, update_output, "Querying DNS databases...\n")
                try:
                    db_subs = query_dns_dbs(domain)
                    discovered.update(db_subs)
                    root.after(0, update_output, f"Found {len(db_subs)} subdomains via DNS databases.\n")
                except Exception as e:
                    root.after(0, update_output, f"Error querying DNS databases: {str(e)}\n")


            if securitytrails_var.get():
                if securitytrails_api_key:
                    root.after(0, update_output, "Querying SecurityTrails...\n")
                    try:
                        st_subs = query_securitytrails(domain, securitytrails_api_key)
                        discovered.update(st_subs)
                        root.after(0, update_output, f"Found {len(st_subs)} subdomains via SecurityTrails.\n")
                    except Exception as e:
                        root.after(0, update_output, f"Error querying SecurityTrails: {str(e)}\n")
                else:
                     root.after(0, update_output, "Skipping SecurityTrails query: API key not provided.\n")


            if zone_transfer_var.get():
                root.after(0, update_output, "Attempting DNS zone transfer...\n")
                try:
                    zt_subs = attempt_zone_transfer(domain)
                    discovered.update(zt_subs)
                    root.after(0, update_output, f"Found {len(zt_subs)} subdomains via zone transfer.\n")
                except Exception as e:
                    root.after(0, update_output, f"Error during zone transfer attempt: {str(e)}\n")


            results = sorted(list(discovered))

            # display results in the main output area
            root.after(0, subdomain_output.insert, tk.END, "\n=== Complete ===\n")
            root.after(0, subdomain_output.insert, tk.END, f"Total unique subdomains found: {len(results)}\n")
            root.after(0, subdomain_output.insert, tk.END, "\n".join(results) + "\n")
            root.after(0, subdomain_output.see, tk.END)


            # enable the other buttons (update in the main thread)
            root.after(0, export_btn.config, state=tk.NORMAL)
            root.after(0, analyze_btn.config, state=tk.NORMAL)
            root.after(0, search_btn.config, state=tk.NORMAL)
            search_btn.data = results # Store results for searching and exporting (can be done in worker thread)

        threading.Thread(target=worker, args=(root,), daemon=True).start()


    def on_search(event=None):
        all_subs = getattr(search_btn, "data", [])
        if not all_subs:
            return

        q = search_entry.get().strip().lower()
        if not q:
            filtered = all_subs
        else:
            filtered = [s for s in all_subs if q in s.lower()]

        # Clear and display filtered results
        subdomain_output.delete("1.0", tk.END)
        if filtered:
            subdomain_output.insert(tk.END, f"Found {len(filtered)} matching subdomains:\n\n")
            subdomain_output.insert(tk.END, "\n".join(filtered) + "\n")
        else:
            subdomain_output.insert(tk.END, "No matching subdomains found.\n")
        subdomain_output.see(tk.END)


    def export_subdomains():
        subs = getattr(search_btn, "data", [])
        if not subs:
            messagebox.showinfo("Export", "No subdomains to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(subs))
            messagebox.showinfo("Export", f"Saved to {path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export subdomains: {str(e)}")


    def analyze_subdomains():
        subs = getattr(search_btn, "data", [])
        if not subs:
            messagebox.showinfo("Analyze", "No subdomains to analyze.")
            return
        # Placeholder for liveness checks or other analysis
        messagebox.showinfo("Analyze", f"Analyzing {len(subs)} subdomains (Analysis not fully implemented).")


    def integrate_with_main():
        subs = getattr(search_btn, "data", [])
        if not subs:
            messagebox.showinfo("Integrate", "No subdomains to send.")
            return
        # Example: pick the first subdomain and insert into the main tab’s entry:
        if subs:
            main_entry.delete(0, tk.END)
            # Prepend https:// for consistency if it's a URL input field
            main_entry.insert(0, f"https://{subs[0]}")
            notebook.select(0)  # switch back to main tab
        else:
             messagebox.showinfo("Integrate", "No subdomains to send.")


    # ── 3) DOMAIN ENTRY AND OPTIONS ────────────────────────────
    domain_frame = ttk.Frame(subdomain_frame)
    domain_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(domain_frame, text="Target Domain:").pack(side=tk.LEFT)
    domain_entry = ttk.Entry(domain_frame, width=40)
    domain_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

    # Add SecurityTrails API Key Entry
    securitytrails_frame = ttk.Frame(subdomain_frame)
    securitytrails_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(securitytrails_frame, text="SecurityTrails API Key:").pack(side=tk.LEFT)
    securitytrails_api_key_entry = ttk.Entry(securitytrails_frame, width=40, show="*")
    securitytrails_api_key_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
     # Optional: Load API key from config if you add it there

    # Add Wordlist Entry
    wordlist_frame = ttk.Frame(subdomain_frame)
    wordlist_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(wordlist_frame, text="Wordlist Path (for bruteforce):").pack(side=tk.LEFT)
    wordlist_entry = ttk.Entry(wordlist_frame, width=40)
    wordlist_entry.insert(0, DEFAULT_WORDLIST) # Default path
    wordlist_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
    ttk.Button(wordlist_frame, text="Browse", command=lambda: on_browse(wordlist_entry)).pack(side=tk.LEFT)


    # Add Checkboxes for Discovery Methods
    methods_frame = ttk.Frame(subdomain_frame)
    methods_frame.pack(fill=tk.X, padx=10, pady=5)

    ttk.Checkbutton(methods_frame, text="Certificate Transparency Logs (crt.sh)", variable=ct_logs_var).pack(side=tk.LEFT, padx=5)
    ttk.Checkbutton(methods_frame, text="DNS Bruteforce", variable=bruteforce_var).pack(side=tk.LEFT, padx=5)
    ttk.Checkbutton(methods_frame, text="DNS Databases (hackertarget, riddler)", variable=dns_dbs_var).pack(side=tk.LEFT, padx=5)
    ttk.Checkbutton(methods_frame, text="SecurityTrails API (requires API key)", variable=securitytrails_var).pack(side=tk.LEFT, padx=5)
    ttk.Checkbutton(methods_frame, text="DNS Zone Transfer Attempt", variable=zone_transfer_var).pack(side=tk.LEFT, padx=5)


    # ── 4) SEARCH ROW ─────────────────────────────────────────
    search_frame = ttk.Frame(subdomain_frame)
    search_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(search_frame, text="Filter Results:").pack(side=tk.LEFT)
    search_entry = ttk.Entry(search_frame, width=40)
    search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
    search_btn = ttk.Button(search_frame, text="Filter", state=tk.DISABLED, command=on_search)
    search_btn.pack(side=tk.LEFT)
    search_entry.bind("<Return>", on_search)

    # ── 5) OUTPUT AREA ────────────────────────────────────────
    subdomain_output = scrolledtext.ScrolledText(
        subdomain_frame, wrap=tk.WORD, width=80, height=15
    )
    subdomain_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    # ── 6) BOTTOM BUTTON BAR ──────────────────────────────────
    button_frame = ttk.Frame(subdomain_frame)
    button_frame.pack(fill=tk.X, padx=10, pady=5)

    discover_btn  = ttk.Button(button_frame, text="Discover Subdomains", command=on_discover)
    export_btn    = ttk.Button(button_frame, text="Export Results",   state=tk.DISABLED, command=export_subdomains)
    analyze_btn   = ttk.Button(button_frame, text="Analyze Live (Not Implemented)",  state=tk.DISABLED, command=analyze_subdomains) # Renamed for clarity
    integrate_btn = ttk.Button(button_frame, text="Send First to Main Tool", command=integrate_with_main) # Renamed for clarity

    for btn in (discover_btn, export_btn, analyze_btn, integrate_btn):
        btn.pack(side=tk.LEFT, padx=5)

    return subdomain_frame

if __name__ == "__main__":
    create_gui()
