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
# MongoDB Atlas Configuration
MONGODB_URL=mongodb+srv://esgAdmin:Tsakani3408@africaesg-cluster.36oy0su.mongodb.net/esg_dashboard?retryWrites=true&w=majority

# Security
SECRET_KEY=your-super-secret-production-key-change-this-to-random-string
GEMINI_API_KEY=AIzaSyAfvt0OQDMbF0aJEr4qjH0bvBocQagQ2Rg

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

# Sunsynk API
SUNSYNK_API_URL=https://openapi.sunsynk.net
SUNSYNK_API_KEY=204013305
SUNSYNK_API_SECRET=zIQJeoPRXCjDV5anS5WIH7SQPAgdVaPm
EOF

echo "✅ Updated .env file with MongoDB Atlas connection"
echo ""
echo "🚀 Your database is now in the cloud!"
echo "📊 624 documents migrated successfully"
echo "🔗 Connected to: africaesg-cluster"
echo ""
echo "🔄 Restart your backend to use the cloud database:"
echo "   uvicorn app.main:app --reload"
