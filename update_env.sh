#!/bin/bash
# Update your .env file with MongoDB Atlas connection

echo "🔧 Updating your .env file with MongoDB Atlas connection..."
echo ""

# Create backup of existing .env
if [ -f ".env" ]; then
    cp .env .env.backup.$(date +%Y%m%d_%H%M%S)
    echo "✅ Backed up existing .env file"
fi

# Update .env file
cat > .env << 'EOF'
# IMPORTANT: placeholders only — DO NOT commit secrets
# Replace the values below with real credentials in your deployment provider (Render / CI)
MONGODB_URL=__REPLACE_WITH_YOUR_MONGODB_URL__

# Security
SECRET_KEY=__REPLACE_WITH_A_STRONG_SECRET_KEY__
GEMINI_API_KEY=__REPLACE_WITH_YOUR_GEMINI_API_KEY__

# Production Settings
DEBUG=False
ENVIRONMENT=production

# CORS Origins (update with your frontend URL)
CORS_ORIGINS=http://localhost:3002,http://localhost:3008,http://localhost:5173,https://yourdomain.com

# Other settings
ACCESS_TOKEN_EXPIRE_MINUTES=30
ALGORITHM=HS256
AUTH_ENABLED=True

# Upload settings
MAX_UPLOAD_SIZE_MB=50
UPLOAD_DIR=./uploads

# Sunsynk API (placeholders)
SUNSYNK_API_URL=https://openapi.sunsynk.net
SUNSYNK_API_KEY=__REPLACE_WITH_SUNSYNK_API_KEY__
SUNSYNK_API_SECRET=__REPLACE_WITH_SUNSYNK_API_SECRET__
EOF

echo "✅ Created a sanitized .env template (please add secrets in your deploy platform)"
echo ""
echo "🔐 REMEMBER: rotate any leaked credentials and remove them from git history" 
echo ""
echo "🔄 Restart your backend to use the updated .env template:"
echo "   uvicorn app.main:app --reload"
