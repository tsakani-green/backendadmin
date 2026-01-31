#!/usr/bin/env python3
"""
Start Real AI Backend with Gemini
This script configures and starts the backend with real Gemini AI
"""

import os
import sys
import subprocess
from pathlib import Path

def check_env_file():
    """Check if .env file exists and has Gemini API key"""
    env_path = Path(".env")
    
    if not env_path.exists():
        print("❌ .env file not found!")
        print("Creating .env file with Gemini configuration...")
        
        env_content = """# ===== Database =====
MONGODB_URL=mongodb://localhost:27017/esg_dashboard

# ===== JWT =====
SECRET_KEY=your-secret-key-here
DEBUG=True

# ===== Gemini =====
GEMINI_API_KEY=__REPLACE_WITH_YOUR_GEMINI_API_KEY__
GEMINI_MODEL_ESG=gemini-1.5-flash
"""
        
        with open(env_path, 'w') as f:
            f.write(env_content)
        
        print("✅ .env file created (please add GEMINI_API_KEY to .env)")
        return True
    
    # Check if Gemini API key is configured
    with open(env_path, 'r') as f:
        content = f.read()
        if "GEMINI_API_KEY=" in content and not content.strip().endswith("GEMINI_API_KEY="):
            print("✅ GEMINI_API_KEY appears to be configured in .env file")
            return True
        else:
            print("❌ GEMINI_API_KEY not found or is empty in .env file!")
            return False

def install_dependencies():
    """Install required dependencies"""
    print("📦 Installing dependencies...")
    
    try:
        # Install Gemini SDK
        subprocess.run([sys.executable, "-m", "pip", "install", "google-generativeai==0.3.2"], 
                      check=True, capture_output=True)
        print("✅ google-generativeai installed")
        
        # Install other required packages
        required_packages = [
            "fastapi==0.104.1",
            "uvicorn[standard]==0.24.0", 
            "python-multipart==0.0.6",
            "pydantic==2.5.0",
            "python-dotenv==1.0.0",
            "numpy==1.24.4"
        ]
        
        for package in required_packages:
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", package], 
                              check=True, capture_output=True)
                print(f"✅ {package} installed")
            except subprocess.CalledProcessError:
                print(f"⚠️  {package} already installed or failed")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def test_gemini_connection():
    """Test Gemini API connection"""
    print("🧪 Testing Gemini API connection...")
    
    try:
        import google.generativeai as genai
        from dotenv import load_dotenv
        
        # Load environment variables
        load_dotenv()
        
        # Get API key
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            print("❌ GEMINI_API_KEY not found in environment!")
            return False
        
        # Configure Gemini
        genai.configure(api_key=api_key)
        
        # Test with a simple request
        model = genai.GenerativeModel('gemini-pro')
        response = model.generate_content("Hello, can you help with ESG analysis?")
        
        print("✅ Gemini API connection successful!")
        print(f"📝 Test response: {response.text[:100]}...")
        return True
        
    except Exception as e:
        print(f"❌ Gemini API connection failed: {e}")
        return False

def start_backend():
    """Start the backend server"""
    print("🚀 Starting backend server...")
    
    try:
        # Start uvicorn
        cmd = [sys.executable, "-m", "uvicorn", "app.main:app", 
               "--reload", "--host", "0.0.0.0", "--port", "8002"]
        
        print("📡 Server starting on http://localhost:8002")
        print("🌐 API docs available at http://localhost:8002/docs")
        print("🤖 Gemini AI endpoints at http://localhost:8002/api/gemini/")
        print("\n⏹️  Press Ctrl+C to stop the server")
        print("=" * 50)
        
        subprocess.run(cmd)
        
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except Exception as e:
        print(f"❌ Error starting server: {e}")

def main():
    """Main setup and start process"""
    print("🌟 ESG Dashboard - Real AI Setup")
    print("=" * 40)
    
    # Change to backend directory
    backend_dir = Path(__file__).parent
    os.chdir(backend_dir)
    print(f"📁 Working directory: {backend_dir}")
    
    # Step 1: Check .env file
    if not check_env_file():
        print("❌ Please configure your Gemini API key in .env file")
        return
    
    # Step 2: Install dependencies
    if not install_dependencies():
        print("❌ Failed to install dependencies")
        return
    
    # Step 3: Test Gemini connection
    if not test_gemini_connection():
        print("❌ Gemini API test failed - will use mock mode")
    
    # Step 4: Start backend
    start_backend()

if __name__ == "__main__":
    main()
