import asyncio
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.api.auth import generate_reset_token, send_password_reset_email

async def test_password_reset():
    print("Testing password reset functionality...")
    
    # Test token generation
    token = generate_reset_token()
    print(f"Generated reset token: {token}")
    print(f"Token length: {len(token)}")
    
    # Test email sending (will print to console for development)
    test_email = "test@example.com"
    email_sent = await send_password_reset_email(test_email, token)
    
    if email_sent:
        print(f"✅ Password reset email sent successfully to {test_email}")
        print(f"📧 Reset link would be: http://localhost:5173/reset-password?token={token}")
    else:
        print("❌ Failed to send password reset email")
    
    print("\nPassword reset test completed!")

if __name__ == "__main__":
    asyncio.run(test_password_reset())
