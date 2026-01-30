# backend/app/services/egauge_client.py

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Tuple, List, Dict, Any
import re
import logging

import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlsplit, urlunsplit, urljoin

from app.core.config import settings

logger = logging.getLogger("egauge.client")


def _auth_tuple() -> Optional[Tuple[str, str]]:
    u = (getattr(settings, "EGAUGE_USERNAME", "") or "").strip()
    p = (getattr(settings, "EGAUGE_PASSWORD", "") or "").strip()
    if u and p:
        return (u, p)
    return None


def _normalize_base_url(raw: str) -> str:
    """
    Keep the user's base path (IMPORTANT: don't truncate /63C1A1).
    Only remove known "suffix" endpoints like:
      .../en_GB/check.html
      .../check.html
      .../cgi-bin/egauge-show
      .../cgi-bin/egauge
    """
    raw = (raw or "").strip()
    if not raw:
        return raw

    parts = urlsplit(raw)
    path = parts.path or ""
    path = path.rstrip("/")

    # If someone pasted the full check.html URL, strip the tail
    if path.endswith("/en_GB/check.html"):
        path = path[: -len("/en_GB/check.html")]
    elif path.endswith("/en/check.html"):
        path = path[: -len("/en/check.html")]
    elif path.endswith("/check.html"):
        path = path[: -len("/check.html")]

    # If base includes /cgi-bin/..., strip from /cgi-bin onward
    if "/cgi-bin/" in path:
        path = path.split("/cgi-bin/", 1)[0]

    # final cleanup
    path = path.rstrip("/")

    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _build_url(base_url: str, suffix: str) -> str:
    base_url = base_url.rstrip("/")
    suffix = suffix.lstrip("/")
    return f"{base_url}/{suffix}"


async def _get_html(url: str) -> httpx.Response:
    async with httpx.AsyncClient(
        timeout=15,
        follow_redirects=True,
        auth=_auth_tuple(),
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        },
        verify=False,  # Some eGauge devices have SSL issues
    ) as client:
        return await client.get(url)


def _extract_local_mains_watts_from_check_html(html: str) -> float:
    soup = BeautifulSoup(html, "html.parser")

    total_watts = 0.0
    found = False

    for row in soup.find_all("tr"):
        cols = [c.get_text(strip=True) for c in row.find_all("td")]
        if len(cols) < 2:
            continue

        register_name = cols[0]
        value_text = cols[1]

        if "local mains" in register_name.lower():
            found = True
            m = re.search(r"([-]?\d+(?:\.\d+)?)\s*W", value_text)
            if m:
                total_watts += float(m.group(1))
                logger.debug(f"Found Local Mains: {m.group(1)} W")

    if not found:
        raise RuntimeError("No 'Local Mains' rows found in check.html HTML")

    return total_watts


async def fetch_check_page_local_mains_watts(base_url: str) -> float:
    """
    Fetch Channel Checker page and sum all "Local Mains" register rows.
    """
    base_url = _normalize_base_url(base_url)

    # Try likely working URLs in a robust order.
    candidate_urls: List[str] = [
        # If base is ".../63C1A1", this becomes ".../63C1A1/en_GB/check.html"
        _build_url(base_url, "en_GB/check.html"),
        _build_url(base_url, "en/check.html"),
        _build_url(base_url, "check.html"),
    ]

    # If user set base_url ".../63C1A1/en_GB", try ".../63C1A1/en_GB/check.html"
    if base_url.endswith("/en_GB"):
        candidate_urls.insert(0, _build_url(base_url, "check.html"))

    logger.debug(f"Trying eGauge URLs: {candidate_urls}")
    last_err: Optional[Exception] = None
    last_response: Optional[httpx.Response] = None

    for url in candidate_urls:
        try:
            logger.debug(f"Attempting to fetch: {url}")
            r = await _get_html(url)

            if r.status_code != 200:
                snippet = (r.text or "")[:200].replace("\n", " ")
                logger.warning(f"HTTP {r.status_code} from {url}: {snippet}")
                last_response = r
                raise RuntimeError(f"HTTP {r.status_code} url={url}")

            watts = _extract_local_mains_watts_from_check_html(r.text)
            logger.info(f"Successfully fetched {watts:.2f} W from {url}")
            return watts

        except Exception as e:
            last_err = e
            logger.debug(f"URL {url} failed: {e}")
            continue

    # Provide detailed error information
    error_msg = f"eGauge check.html failed. Last error: {last_err}"
    if last_response:
        error_msg += f"\nLast response: HTTP {last_response.status_code}"
        if last_response.text:
            error_msg += f"\nBody preview: {last_response.text[:500]}"
    
    raise RuntimeError(error_msg)


async def fetch_check_page_register_watts(base_url: str) -> dict:
    """
    Normalized payload for frontend.
    """
    watts = await fetch_check_page_local_mains_watts(base_url)
    kw = watts / 1000.0

    ts = datetime.now(timezone.utc).isoformat()

    return {
        "site": "bertha-house",
        "power_kw": round(kw, 3),
        "energy_kwh_delta": 0.0,
        "cost_zar_delta": 0.0,
        "ts_utc": ts,
        "source": "egauge_check_html",
        "raw_local_mains_w": round(watts, 2),
        "poll_timestamp": ts,
    }


# ===== DIAGNOSTIC FUNCTIONS =====

async def diagnose_egauge_connection(base_url: str) -> List[Dict[str, Any]]:
    """Diagnostic function to help debug eGauge connection issues"""
    base_url = base_url.rstrip("/")
    
    # Test different endpoints
    endpoints = [
        "",  # root
        "en_GB/check.html",
        "en/check.html", 
        "check.html",
        "cgi-bin/egauge",
        "cgi-bin/egauge-show",
        "cgi-bin/egauge?inst",
        "cgi-bin/egauge?tot",
    ]
    
    results = []
    auth = _auth_tuple()
    
    async with httpx.AsyncClient(
        timeout=10,
        follow_redirects=True,
        auth=auth,
        headers={
            "User-Agent": "AfricaESG.AI/egauge-diagnostic",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        verify=False,
    ) as client:
        for endpoint in endpoints:
            url = urljoin(base_url + "/", endpoint) if endpoint else base_url
            try:
                response = await client.get(url)
                
                # Check for specific patterns in successful responses
                analysis = {}
                if response.status_code == 200 and response.text:
                    text_lower = response.text.lower()
                    if "local mains" in text_lower:
                        analysis["has_local_mains"] = True
                    if "<html" in text_lower:
                        analysis["is_html"] = True
                    if "<?xml" in response.text[:100].lower():
                        analysis["is_xml"] = True
                    if "egauge" in text_lower:
                        analysis["mentions_egauge"] = True
                
                result = {
                    "url": url,
                    "status": response.status_code,
                    "content_type": response.headers.get("content-type", ""),
                    "content_length": len(response.text),
                    "analysis": analysis,
                    "error": None,
                    "auth_used": bool(auth),
                }
                results.append(result)
                    
            except Exception as e:
                results.append({
                    "url": url,
                    "status": None,
                    "error": str(e),
                    "auth_used": bool(auth),
                })
    
    return results


async def test_egauge_auth(base_url: str) -> Dict[str, Any]:
    """Test eGauge authentication"""
    auth = _auth_tuple()
    base_url = base_url.rstrip("/")
    test_url = f"{base_url}/check.html"
    
    results = {}
    
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            # Try without auth first
            response_no_auth = await client.get(test_url)
            results["without_auth"] = {
                "status": response_no_auth.status_code,
                "requires_auth": response_no_auth.status_code == 401,
                "content_type": response_no_auth.headers.get("content-type", ""),
            }
            
            # Try with auth if configured
            if auth:
                response_with_auth = await client.get(test_url, auth=auth)
                results["with_auth"] = {
                    "status": response_with_auth.status_code,
                    "success": response_with_auth.status_code == 200,
                    "content_type": response_with_auth.headers.get("content-type", ""),
                }
            
            results["auth_configured"] = bool(auth)
            results["test_url"] = test_url
            
    except Exception as e:
        results["error"] = str(e)
        results["test_url"] = test_url
    
    return results