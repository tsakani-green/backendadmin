# backend/debug_egauge.py

import asyncio
import httpx
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_all_endpoints():
    """Test ALL possible eGauge endpoints to find the correct one"""
    
    # Get your configuration
    from app.core.config import settings
    
    base_url = "https://egauge65730.egaug.es"
    install_id = "63C1A1"
    
    # ALL possible endpoints to test
    endpoints = [
        # Basic structure variations
        f"{install_id}",
        f"{install_id}/",
        
        # With language variations
        f"{install_id}/en_GB",
        f"{install_id}/en_GB/",
        f"{install_id}/en",
        f"{install_id}/en/",
        
        # Check.html variations
        f"{install_id}/en_GB/check.html",
        f"{install_id}/en/check.html",
        f"{install_id}/check.html",
        
        # API endpoints
        f"{install_id}/cgi-bin/egauge",
        f"{install_id}/cgi-bin/egauge?inst",
        f"{install_id}/cgi-bin/egauge?tot",
        f"{install_id}/cgi-bin/egauge-show",
        f"{install_id}/cgi-bin/egauge-show?S",
        
        # XML endpoints
        f"{install_id}/cgi-bin/egauge?XML=1",
        f"{install_id}/cgi-bin/egauge?inst&XML=1",
        f"{install_id}/cgi-bin/egauge?tot&XML=1",
        
        # JSON endpoints (some devices support this)
        f"{install_id}/cgi-bin/egauge?JSON=1",
        f"{install_id}/cgi-bin/egauge?inst&JSON=1",
        
        # Historical endpoints
        f"{install_id}/cgi-bin/egauge-history",
        f"{install_id}/cgi-bin/egauge-history?T=0",
        
        # Web interface endpoints
        f"{install_id}/index.html",
        f"{install_id}/home.html",
        f"{install_id}/main.html",
        
        # Configuration endpoints
        f"{install_id}/config.html",
        f"{install_id}/setup.html",
        
        # Device info
        f"{install_id}/about.html",
        f"{install_id}/info.html",
    ]
    
    auth = None
    if settings.EGAUGE_USERNAME and settings.EGAUGE_PASSWORD:
        auth = httpx.BasicAuth(settings.EGAUGE_USERNAME, settings.EGAUGE_PASSWORD)
    
    print("="*80)
    print(f"Testing eGauge device: {base_url}")
    print(f"Install ID: {install_id}")
    print(f"Authentication: {'Enabled' if auth else 'Disabled'}")
    print("="*80)
    
    results = []
    
    async with httpx.AsyncClient(
        timeout=10,
        verify=False,
        auth=auth,
        follow_redirects=True,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
    ) as client:
        for endpoint in endpoints:
            url = f"{base_url}/{endpoint}"
            try:
                print(f"\nTesting: {url}")
                
                # Try with GET first
                response = await client.get(url)
                status = response.status_code
                
                if status == 200:
                    print(f"  ✅ HTTP {status} - SUCCESS!")
                    
                    # Check content type
                    content_type = response.headers.get('content-type', '')
                    print(f"  Content-Type: {content_type}")
                    
                    # Check if it's HTML/XML we can parse
                    if 'html' in content_type.lower() or 'xml' in content_type.lower():
                        content = response.text[:500]
                        # Check for keywords
                        keywords = ['egauge', 'local mains', 'power', 'watts', 'xml']
                        found = [kw for kw in keywords if kw.lower() in content.lower()]
                        if found:
                            print(f"  Contains: {', '.join(found)}")
                        
                        # Show snippet
                        print(f"  Preview: {content[:100]}...")
                    
                    results.append((url, status, "SUCCESS", content_type))
                    
                elif status == 401:
                    print(f"  🔒 HTTP {status} - Authentication required")
                    results.append((url, status, "AUTH_REQUIRED", ""))
                    
                elif status == 400:
                    print(f"  ❌ HTTP {status} - Bad Request")
                    # Try with different headers
                    print("  Trying with different headers...")
                    
                    # Try with no User-Agent
                    try:
                        r2 = await client.get(url, headers={"User-Agent": ""})
                        if r2.status_code != 400:
                            print(f"  ⚠️  Changed to HTTP {r2.status_code} with no User-Agent")
                    except:
                        pass
                    
                    # Try with XML accept
                    try:
                        r3 = await client.get(url, headers={"Accept": "application/xml"})
                        if r3.status_code != 400:
                            print(f"  ⚠️  Changed to HTTP {r3.status_code} with XML Accept")
                    except:
                        pass
                    
                    results.append((url, status, "BAD_REQUEST", ""))
                    
                elif status == 404:
                    print(f"  ❌ HTTP {status} - Not Found")
                    results.append((url, status, "NOT_FOUND", ""))
                    
                else:
                    print(f"  ⚠️  HTTP {status} - Unexpected")
                    results.append((url, status, "OTHER", ""))
                    
            except Exception as e:
                print(f"  💥 ERROR: {type(e).__name__}: {e}")
                results.append((url, None, f"ERROR: {e}", ""))
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    successes = [r for r in results if r[1] == 200]
    auth_required = [r for r in results if r[1] == 401]
    bad_requests = [r for r in results if r[1] == 400]
    not_found = [r for r in results if r[1] == 404]
    
    print(f"Successful (200): {len(successes)}")
    print(f"Auth Required (401): {len(auth_required)}")
    print(f"Bad Request (400): {len(bad_requests)}")
    print(f"Not Found (404): {len(not_found)}")
    
    if successes:
        print("\nSuccessful endpoints:")
        for url, status, result, content_type in successes[:5]:  # Show first 5
            print(f"  ✅ {url}")
            if content_type:
                print(f"     Content-Type: {content_type}")
    
    if auth_required:
        print("\nAuthentication required endpoints:")
        for url, status, result, _ in auth_required[:3]:
            print(f"  🔒 {url}")
    
    return len(successes) > 0


async def test_manual_url():
    """Test a manually specified URL"""
    url = input("\nEnter a URL to test manually (or press Enter to skip): ").strip()
    
    if not url:
        return
    
    from app.core.config import settings
    
    auth = None
    if settings.EGAUGE_USERNAME and settings.EGAUGE_PASSWORD:
        auth = httpx.BasicAuth(settings.EGAUGE_USERNAME, settings.EGAUGE_PASSWORD)
    
    async with httpx.AsyncClient(
        timeout=10,
        verify=False,
        auth=auth,
        follow_redirects=True,
        headers={
            "User-Agent": "Mozilla/5.0",
            "Accept": "*/*",
        }
    ) as client:
        try:
            print(f"\nTesting: {url}")
            response = await client.get(url)
            
            print(f"Status: HTTP {response.status_code}")
            print(f"Headers: {dict(response.headers)}")
            
            if response.status_code == 200:
                print("\nResponse body (first 1000 chars):")
                print(response.text[:1000])
                
                # Save to file for inspection
                with open("egauge_response.html", "w", encoding="utf-8") as f:
                    f.write(response.text)
                print(f"\nFull response saved to: egauge_response.html")
                
        except Exception as e:
            print(f"Error: {e}")


async def test_with_curl_commands():
    """Generate curl commands to test manually"""
    base_url = "https://egauge65730.egaug.es"
    install_id = "63C1A1"
    
    print("\n" + "="*80)
    print("CURL COMMANDS TO TEST MANUALLY")
    print("="*80)
    
    # Basic test
    print("\n1. Basic test (no auth):")
    print(f'   curl -k "{base_url}/{install_id}/"')
    
    # With auth if configured
    from app.core.config import settings
    if settings.EGAUGE_USERNAME and settings.EGAUGE_PASSWORD:
        print(f"\n2. With authentication:")
        print(f'   curl -k -u "{settings.EGAUGE_USERNAME}:{settings.EGAUGE_PASSWORD}" "{base_url}/{install_id}/"')
    
    # With verbose output
    print(f"\n3. With verbose output:")
    print(f'   curl -k -v "{base_url}/{install_id}/"')
    
    # Test different accept headers
    print(f"\n4. With XML accept header:")
    print(f'   curl -k -H "Accept: application/xml" "{base_url}/{install_id}/cgi-bin/egauge"')
    
    print(f"\n5. With no User-Agent:")
    print(f'   curl -k -H "User-Agent:" "{base_url}/{install_id}/"')
    
    print("\n" + "="*80)


async def check_network():
    """Check network connectivity to eGauge"""
    import socket
    from urllib.parse import urlparse
    
    base_url = "https://egauge65730.egaug.es"
    
    print("\n" + "="*80)
    print("NETWORK CONNECTIVITY CHECK")
    print("="*80)
    
    parsed = urlparse(base_url)
    hostname = parsed.hostname
    port = parsed.port or 443
    
    # DNS resolution
    try:
        ip = socket.gethostbyname(hostname)
        print(f"✅ DNS Resolution: {hostname} → {ip}")
    except socket.gaierror as e:
        print(f"❌ DNS Resolution failed: {e}")
        return False
    
    # Port connectivity
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            print(f"✅ Port {port} is open on {ip}")
        else:
            print(f"❌ Port {port} is closed on {ip}")
            return False
    except Exception as e:
        print(f"❌ Port check failed: {e}")
        return False
    
    # SSL certificate check
    import ssl
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(f"✅ SSL Certificate: Valid until {cert['notAfter']}")
    except Exception as e:
        print(f"⚠️  SSL Certificate check: {e}")
    
    return True


async def main():
    """Main debug function"""
    print("eGauge Device Debug Tool")
    print()
    
    # Check network first
    network_ok = await check_network()
    if not network_ok:
        print("\n❌ Network connectivity issue detected!")
        return False
    
    # Test all endpoints
    print("\nStarting endpoint discovery...")
    success = await test_all_endpoints()
    
    # Generate curl commands
    await test_with_curl_commands()
    
    # Test manual URL
    await test_manual_url()
    
    return success


if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)