"""
DEMO FILE — intentionally insecure code to show live scanning.
Remove before final submission.
"""
import subprocess

# Hardcoded secret — Gitleaks should catch this
API_SECRET = "demo_key_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
def run_backup(filename):
    # Command injection — Semgrep should catch this
    subprocess.run(f"tar -cvf backup.tar {filename}", shell=True)

def get_user(db, user_id):
    # SQL injection — Semgrep should catch this
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
