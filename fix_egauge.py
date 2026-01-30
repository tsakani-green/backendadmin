# backend/fix_egauge.py

import asyncio
import httpx
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def find_correct_url():
    """The most common eGauge URL patterns"""
    
    base_domain = "https://egauge65730.egaug.es"
    
    # COMMON eGauge URL patterns (based on your logs showing lighttpd/1.4.45)
    patterns = [
        # Pattern 1: Direct install ID
        f"{base_domain}/{install_id}",
        
        # Pattern 2: With .egaug.es subdomain (most common)
        f"https://{install_id}.egaug.es",
        
        # Pattern 3: With .d.egaug.es subdomain (some installations)
        f"https://{install_id}.d.egaug.es",
        
        # Pattern 4: With numeric prefix
        f"{base_domain}/egauge{install_id}",
        
        # Pattern 5: Without https (some older devices)
        f"http://{install_id}.egaug.es",
        
        # Pattern 6: With www
        f"https://www.{install_id}.egaug.es",
    ]
    
    print("Testing common eGauge URL patterns...")
    print("="*60)
    
    for pattern in patterns:
        for install_id in ["63C1A1", "63C1A"]:  # Try with and without the '1'
            url = pattern.replace("{install_id}", install_id)
            
            try:
                async with httpx.AsyncClient(timeout=5, verify=False) as client:
                    response = await client.get(f"{url}/", follow_redirects=True)
                    
                    if response.status_code == 200:
                        print(f"✅ FOUND WORKING URL: {url}/")
                        
                        # Check if it looks like eGauge
                        if "egauge" in response.text.lower():
                            print(f"   Confirmed: Contains 'egauge' in response")
                        
                        # Try check.html
                        check_response = await client.get(f"{url}/check.html")
                        if check_response.status_code == 200:
                            print(f"   check.html also works!")
                        
                        return url
                    elif response.status_code == 401:
                        print(f"🔒 {url}/ - Authentication required (GOOD SIGN!)")
                        return url
                    elif response.status_code != 400:
                        print(f"⚠️  {url}/ - HTTP {response.status_code}")
                        
            except Exception as e:
                # Silently skip connection errors
                pass
    
    print("\nNo working URL found with common patterns.")
    print("\nLet's try to discover the correct URL...")
    
    # Try to brute-force discover
    test_urls = [
        "https://egauge65730.egaug.es",
        "https://63C1A1.egaug.es",
        "https://63C1A.egaug.es",
        "https://egauge-63C1A1.egaug.es",
        "https://egauge63C1A1.egaug.es",
        "https://e65730.egaug.es",  # Sometimes it's just the numeric part
    ]
    
    for url in test_urls:
        try:
            async with httpx.AsyncClient(timeout=5, verify=False) as client:
                response = await client.get(url, follow_redirects=True)
                
                if response.status_code == 200:
                    print(f"\n✅ DISCOVERED: {url}")
                    print(f"   Status: HTTP {response.status_code}")
                    
                    # Check server header
                    server = response.headers.get('server', '')
                    if 'lighttpd' in server:
                        print(f"   Server: {server} (Matches your device!)")
                    
                    # Check content
                    if '<html' in response.text.lower():
                        print(f"   Content: HTML page")
                        if 'egauge' in response.text.lower():
                            print(f"   Contains 'egauge' - This is likely correct!")
                            return url
                    
                    return url
                    
        except Exception as e:
            continue
    
    return None


async def test_with_proper_headers():
    """Test with headers that eGauge might expect"""
    
    url = "https://egauge65730.egaug.es/63C1A1"
    
    headers_list = [
        {"User-Agent": "eGauge/1.0"},
        {"User-Agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)"},  # Old IE
        {"User-Agent": ""},  # No User-Agent
        {"User-Agent": "curl/7.68.0"},  # curl
    ]
    
    print("\n" + "="*60)
    print("Testing with different User-Agent headers...")
    print("="*60)
    
    for headers in headers_list:
        try:
            async with httpx.AsyncClient(timeout=5, verify=False) as client:
                response = await client.get(f"{url}/check.html", headers=headers)
                print(f"User-Agent: {headers.get('User-Agent', 'None')[:30]}...")
                print(f"  Status: HTTP {response.status_code}")
                
                if response.status_code != 400:
                    print(f"  ⚠️  Different status with this User-Agent!")
                    
        except Exception as e:
            print(f"  Error: {e}")


async def check_auth_issue():
    """Check if authentication is the problem"""
    
    from app.core.config import settings
    
    url = "https://egauge65730.egaug.es/63C1A1/check.html"
    
    print("\n" + "="*60)
    print("Testing authentication...")
    print("="*60)
    
    # Test 1: No auth
    try:
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            response = await client.get(url)
            print(f"No authentication: HTTP {response.status_code}")
    except Exception as e:
        print(f"No authentication: Error - {e}")
    
    # Test 2: With configured auth
    if settings.EGAUGE_USERNAME and settings.EGAUGE_PASSWORD:
        auth = httpx.BasicAuth(settings.EGAUGE_USERNAME, settings.EGAUGE_PASSWORD)
        try:
            async with httpx.AsyncClient(timeout=5, verify=False, auth=auth) as client:
                response = await client.get(url)
                print(f"With auth '{settings.EGAUGE_USERNAME}': HTTP {response.status_code}")
        except Exception as e:
            print(f"With auth: Error - {e}")
    
    # Test 3: Common eGauge credentials
    common_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", ""),
        ("user", "user"),
        ("egauge", "egauge"),
    ]
    
    for username, password in common_creds:
        auth = httpx.BasicAuth(username, password)
        try:
            async with httpx.AsyncClient(timeout=3, verify=False, auth=auth) as client:
                response = await client.get(url)
                if response.status_code != 400:  # If it changes from 400
                    print(f"With common creds '{username}': HTTP {response.status_code}")
        except:
            pass


async def main():
    print("eGauge URL Discovery Tool")
    print()
    
    # Step 1: Find correct URL pattern
    correct_url = await find_correct_url()
    
    if correct_url:
        print(f"\n🎯 RECOMMENDED URL: {correct_url}")
        print(f"\nUpdate your .env file with:")
        print(f'EGAUGE_BASE_URL="{correct_url}"')
        
        # Test the recommended URL
        print(f"\nTesting recommended URL...")
        try:
            async with httpx.AsyncClient(timeout=5, verify=False) as client:
                response = await client.get(f"{correct_url}/check.html")
                print(f"check.html: HTTP {response.status_code}")
                
                response = await client.get(f"{correct_url}/cgi-bin/egauge")
                print(f"cgi-bin/egauge: HTTP {response.status_code}")
        except Exception as e:
            print(f"Test error: {e}")
    
    # Step 2: Test headers
    await test_with_proper_headers()
    
    # Step 3: Check authentication
    await check_auth_issue()
    
    print("\n" + "="*60)
    print("NEXT STEPS:")
    print("1. Try the curl commands from the debug script")
    print("2. Check if the device has a web interface")
    print("3. Contact eGauge support with your device ID: 63C1A1")
    print("4. Try accessing from a web browser directly")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(main())