# backend/find_egauge_url.py

import asyncio
import httpx
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_all_possible_urls():
    """Test ALL possible eGauge URL patterns"""
    
    # WARNING: do NOT commit real credentials. Replace these placeholders locally.
    username = "__REPLACE_WITH_EGAUGE_USERNAME__"
    password = "__REPLACE_WITH_EGAUGE_PASSWORD__"
    auth = httpx.BasicAuth(username, password)
    
    print("="*80)
    print("Testing with placeholder credentials (do NOT commit real secrets)")
    print("="*80)
    
    # ALL possible URL patterns for eGauge
    base_patterns = [
        # Pattern 1: Subdomain with install ID (MOST COMMON)
        "https://{id}.egaug.es",
        "http://{id}.egaug.es",
        
        # Pattern 2: Subdomain with egauge prefix
        "https://egauge{id}.egaug.es",
        "http://egauge{id}.egaug.es",
        
        # Pattern 3: Subdomain with e prefix
        "https://e{id}.egaug.es",
        "http://e{id}.egaug.es",
        
        # Pattern 4: Your current pattern
        "https://egauge65730.egaug.es/{id}",
        "http://egauge65730.egaug.es/{id}",
        
        # Pattern 5: With different domain
        "https://{id}.egaug.com",
        "https://egauge{id}.egaug.com",
        
        # Pattern 6: Direct IP (from DNS lookup)
        "https://165.227.251.141/{id}",
        "http://165.227.251.141/{id}",
        
        # Pattern 7: With port
        "https://{id}.egaug.es:443",
        "http://{id}.egaug.es:80",
        
        # Pattern 8: Different subdomain pattern
        "https://egauge{id}.d.egaug.es",
        "https://{id}.d.egaug.es",
    ]
    
    # Try different ID variations
    id_variations = [
        "63C1A1",  # Your ID
        "63C1A",   # Without the last '1'
        "63C1A11", # With extra '1'
        "65730",   # Just the numeric part
        "egauge65730", # Full
    ]
    
    successful_urls = []
    
    async with httpx.AsyncClient(
        timeout=10,
        verify=False,
        auth=auth,
        follow_redirects=True,
        headers={
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html,application/xhtml+xml",
        }
    ) as client:
        
        total_tests = len(base_patterns) * len(id_variations)
        test_count = 0
        
        for base_pattern in base_patterns:
            for install_id in id_variations:
                test_count += 1
                url = base_pattern.replace("{id}", install_id)
                
                # Clean URL (remove double slashes, etc.)
                url = url.replace("//", "/").replace(":/", "://")
                
                print(f"\nTest {test_count}/{total_tests}: {url}")
                
                # Test the root URL
                try:
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        print(f"  ✅ ROOT: HTTP 200 - SUCCESS!")
                        
                        # Check if it looks like eGauge
                        content_lower = response.text.lower()
                        if any(keyword in content_lower for keyword in ['egauge', 'power', 'meter', 'energy']):
                            print(f"  🔍 Contains eGauge keywords")
                        
                        # Test check.html
                        check_url = f"{url.rstrip('/')}/check.html"
                        try:
                            check_response = await client.get(check_url)
                            if check_response.status_code == 200:
                                print(f"  ✅ check.html also works!")
                                if 'local mains' in check_response.text.lower():
                                    print(f"  🔍 Contains 'Local Mains'")
                            else:
                                print(f"  ⚠️  check.html: HTTP {check_response.status_code}")
                        except:
                            pass
                        
                        successful_urls.append((url, "ROOT_200", response.text[:100]))
                        
                    elif response.status_code == 401:
                        print(f"  🔒 ROOT: HTTP 401 - Authentication failed (wrong credentials?)")
                        
                    elif response.status_code == 400:
                        # Try a different path
                        test_paths = [
                            f"{url}/cgi-bin/egauge",
                            f"{url}/cgi-bin/egauge-show",
                            f"{url}/en/check.html",
                            f"{url}/en_GB/check.html",
                        ]
                        
                        for test_path in test_paths:
                            try:
                                path_response = await client.get(test_path)
                                if path_response.status_code == 200:
                                    print(f"  ✅ {test_path}: HTTP 200!")
                                    successful_urls.append((test_path, "PATH_200", ""))
                                    break
                                elif path_response.status_code != 400:
                                    print(f"  ⚠️  {test_path}: HTTP {path_response.status_code}")
                            except:
                                pass
                        
                    elif response.status_code == 404:
                        print(f"  ❌ ROOT: HTTP 404 - Not found")
                        
                    else:
                        print(f"  ⚠️  ROOT: HTTP {response.status_code}")
                        
                except httpx.ConnectError:
                    print(f"  🔌 Connection failed")
                except Exception as e:
                    print(f"  💥 Error: {type(e).__name__}")
    
    # Summary
    print("\n" + "="*80)
    print("DISCOVERY SUMMARY")
    print("="*80)
    
    if successful_urls:
        print(f"\n🎯 FOUND {len(successful_urls)} POTENTIAL URLS:")
        for url, result_type, preview in successful_urls:
            print(f"\n  {url}")
            print(f"  Type: {result_type}")
            if preview:
                print(f"  Preview: {preview}...")
    else:
        print("\n❌ No working URLs found with current credentials.")
        print("\nPossible issues:")
        print("1. The URL pattern is completely different")
        print("2. Credentials are incorrect")
        print("3. Device is in maintenance mode")
        print("4. IP/domain blocking")
    
    return successful_urls


async def test_without_auth():
    """Test common URLs without authentication"""
    
    print("\n" + "="*80)
    print("TESTING WITHOUT AUTHENTICATION")
    print("="*80)
    
    common_urls = [
        "https://63C1A1.egaug.es",
        "https://egauge63C1A1.egaug.es",
        "https://63C1A1.d.egaug.es",
        "https://e65730.egaug.es",
        "https://egauge65730.egaug.es",
    ]
    
    async with httpx.AsyncClient(
        timeout=5,
        verify=False,
        follow_redirects=True,
    ) as client:
        
        for url in common_urls:
            try:
                response = await client.get(url)
                print(f"\n{url}")
                print(f"  Status: HTTP {response.status_code}")
                
                if response.status_code == 200:
                    print(f"  ✅ Works without auth!")
                    
                    # Check server header
                    server = response.headers.get('server', '')
                    if server:
                        print(f"  Server: {server}")
                    
                    # Check for eGauge
                    if 'egauge' in response.text.lower():
                        print(f"  🔍 Contains 'egauge'")
                        
                elif response.status_code == 401:
                    print(f"  🔒 Requires authentication")
                    
            except Exception as e:
                print(f"\n{url}")
                print(f"  Error: {type(e).__name__}")


async def brute_force_subdomains():
    """Brute force common subdomain patterns"""
    
    print("\n" + "="*80)
    print("BRUTE FORCING COMMON SUBDOMAIN PATTERNS")
    print("="*80)
    
    patterns = [
        "{id}",
        "egauge{id}",
        "e{id}",
        "meter{id}",
        "device{id}",
        "{id}-device",
        "{id}-meter",
    ]
    
    ids = ["63C1A1", "65730", "63C1A", "C1A1", "1A1"]
    
    async with httpx.AsyncClient(
        timeout=3,
        verify=False,
        follow_redirects=True,
    ) as client:
        
        for pattern in patterns:
            for install_id in ids:
                subdomain = pattern.replace("{id}", install_id)
                url = f"https://{subdomain}.egaug.es"
                
                try:
                    response = await client.get(url)
                    if response.status_code == 200:
                        print(f"✅ {url} - HTTP 200")
                    elif response.status_code == 401:
                        print(f"🔒 {url} - HTTP 401 (requires auth)")
                    # Don't print 400/404 to reduce noise
                        
                except:
                    pass


async def check_web_browser_access():
    """Instructions for manual browser testing"""
    
    print("\n" + "="*80)
    print("MANUAL TESTING INSTRUCTIONS")
    print("="*80)
    
    print("\n1. Open a web browser and try these URLs:")
    print("   https://63C1A1.egaug.es")
    print("   https://egauge63C1A1.egaug.es")
    print("   https://63C1A1.d.egaug.es")
    print("   https://egauge65730.egaug.es")
    
    print("\n2. If prompted for authentication, use (placeholders):")
    print("   Username: __REPLACE_WITH_EGAUGE_USERNAME__")
    print("   Password: __REPLACE_WITH_EGAUGE_PASSWORD__")
    
    print("\n3. Look for:")
    print("   - eGauge logo or branding")
    print("   - Power/meter readings")
    print("   - 'Local Mains' mentioned")
    print("   - Menu with 'Channel Checker'")
    
    print("\n4. Check the URL in address bar when you see the meter data")
    print("   That's the correct URL to use in your .env file")


async def generate_curl_test_commands():
    """Generate specific curl commands to test"""
    
    print("\n" + "="*80)
    print("TARGETED CURL COMMANDS TO RUN")
    print("="*80)
    
    auth = "__REPLACE_WITH_EGAUGE_USERNAME__:__REPLACE_WITH_EGAUGE_PASSWORD__"
    
    commands = [
        # Most likely correct pattern
        f'curl -k -u "{auth}" "https://63C1A1.egaug.es/" -v',
        f'curl -k -u "{auth}" "https://63C1A1.egaug.es/check.html" -v',
        
        # Alternative patterns
        f'curl -k -u "{auth}" "https://egauge63C1A1.egaug.es/" -v',
        f'curl -k -u "{auth}" "https://63C1A1.d.egaug.es/" -v',
        
        # Try without auth first
        'curl -k "https://63C1A1.egaug.es/" -v',
        'curl -k "https://egauge65730.egaug.es/" -v',
        
        # Try with IP address
        f'curl -k -u "{auth}" "https://165.227.251.141/" -v',
        f'curl -k -u "{auth}" "https://165.227.251.141/63C1A1/" -v',
    ]
    
    for i, cmd in enumerate(commands, 1):
        print(f"\n{i}. {cmd}")


async def main():
    print("eGauge URL Discovery Tool")
    print()
    
    # Test with authentication
    print("Searching for correct eGauge URL with your credentials...")
    successful_urls = await test_all_possible_urls()
    
    # Test without authentication
    await test_without_auth()
    
    # Brute force common patterns
    await brute_force_subdomains()
    
    # Generate curl commands
    await generate_curl_test_commands()
    
    # Browser instructions
    await check_web_browser_access()
    
    print("\n" + "="*80)
    print("RECOMMENDATION")
    print("="*80)
    
    if successful_urls:
        best_url = successful_urls[0][0]
        print(f"\n🎯 Use this URL in your .env file:")
        print(f'EGAUGE_BASE_URL="{best_url}"')
    else:
        print("\n⚠️  No automatic discovery worked.")
        print("\nPlease try:")
        print("1. The curl commands above")
        print("2. Manual browser testing")
        print("3. Contact the eGauge device administrator")
        print("\nThe most likely correct URL is: https://63C1A1.egaug.es")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)