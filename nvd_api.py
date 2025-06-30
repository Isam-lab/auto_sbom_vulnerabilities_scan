import requests
from utils import log_error, NVD_API_KEY
from dotenv import load_dotenv

# Load .env variables (e.g., NVD_API_KEY)
load_dotenv()

# Standard headers for NVD API requests
HEADERS = {
    "apiKey": NVD_API_KEY,
    "User-Agent": "SBOM-Vuln-Scanner/1.0"
}

def sanitize_cpe(cpe_str):
    """
    Normalize a CPE string by trimming it to the first 9 parts.
    This prevents version mismatch errors in NVD API queries.
    """
    parts = cpe_str.split(':')
    return ':'.join(parts[:9]) if len(parts) >= 9 else cpe_str

def query_cves_by_cpe(cpe_name):
    """
    Query the NVD API for all CVEs that match a given CPE string.
    Returns a list of simplified CVE dictionaries.
    """
    clean_cpe = sanitize_cpe(cpe_name)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cpeName": clean_cpe}

    response = requests.get(url, headers=HEADERS, params=params)
    if response.status_code == 404:
        log_error(f"No CVEs found for {clean_cpe} (NVD 404)")
        return []
    if response.status_code < 200 or response.status_code >= 300:
        msg = f"Failed to query CVEs for CPE {clean_cpe} - status code {response.status_code}"
        log_error(msg)
        return []

    results = response.json().get("vulnerabilities", [])
    return [extract_cve_info(item.get("cve", {})) for item in results if "cve" in item]

def extract_cve_info(cve_data):
    """
    Parse a single CVE object from the NVD API response.
    Returns a dictionary with ID, description, CVSS metrics, and references.
    """
    cve_id = cve_data.get("id", "UNKNOWN")

    # Extract CVSS scores from all supported versions
    metrics = cve_data.get("metrics", {})
    cvss_data = {}
    cvss_summary_lines = []
    found_metric = False
    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version_key in metrics and not found_metric:
            scores = [
                {
                    "baseScore": m.get("cvssData", {}).get("baseScore"),
                    "vector": m.get("cvssData", {}).get("vectorString")
                }
                for m in metrics[version_key]
            ]
            cvss_data[version_key] = scores
            for score in scores:
                line = f"- {version_key}: {score['baseScore']} ({score['vector']})"
                if line not in cvss_summary_lines:
                    cvss_summary_lines.append(line)
            found_metric = True  # Nur ein Block aufnehmen

    # Format CVSS section with bold label
    cvss_summary = "**CVSS:**\n" + "\n".join(cvss_summary_lines) if cvss_summary_lines else ""

    refs = [ref["url"] for ref in cve_data.get("references", []) if "url" in ref]
    unique_refs = list(dict.fromkeys(refs))  # Remove duplicates
    formatted_refs = "**References:**\n" + "\n".join([f"- {url}" for url in unique_refs]) if unique_refs else ""

    # Use English-language description
    descriptions = cve_data.get("descriptions", [])
    desc_text = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")

    return {
        "id": cve_id,
        "description": f"{desc_text.strip()}\n\n{cvss_summary}\n\n{formatted_refs}",
        "cvss": cvss_data,
        "references": refs
    }

def fuzzy_search_cpe(product_name, version):
    """
    Try to identify a valid CPE name by performing a fuzzy search
    based on the component name and version.
    Returns a list of matching CPE names.
    """
    query = f"{product_name.strip().lower().replace(' ', '')} {version.strip().lower().replace(' ', '')}"
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    params = {"keywordSearch": query, "resultsPerPage": 5}

    response = requests.get(url, headers=HEADERS, params=params)
    if response.status_code < 200 or response.status_code >= 300:
        msg = f"Fuzzy CPE search failed for '{query}' – status code {response.status_code}"
        log_error(msg)
        return []

    products = response.json().get("products", [])
    if not products:
        log_error(f"No CPEs found for '{query}'")
        return []

    return [p["cpe"]["cpeName"] for p in products if "cpe" in p and "cpeName" in p["cpe"]]
