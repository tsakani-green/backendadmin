from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Test the stored hash
stored_hash = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/RK.s5uO.G"
password = "admin123"

print(f"Testing password: {password}")
print(f"Stored hash: {stored_hash}")
print(f"Verification result: {verify_password(password, stored_hash)}")

# Test creating a new hash
new_hash = pwd_context.hash(password)
print(f"New hash: {new_hash}")
print(f"New hash verification: {verify_password(password, new_hash)}")
