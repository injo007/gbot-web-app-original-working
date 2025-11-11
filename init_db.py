
import os
import sys
import psycopg2
from werkzeug.security import generate_password_hash

def get_db_connection():
    """Establishes a connection to the database using environment variables."""
    try:
        # The setup script exports DATABASE_URL, but psycopg2 needs individual params.
        # We will parse the DATABASE_URL if the specific env vars are not set.
        db_url = os.environ.get("DATABASE_URL")
        if db_url:
            # Format: postgresql://user:password@host:port/dbname
            from urllib.parse import urlparse
            result = urlparse(db_url)
            user = result.username
            password = result.password
            dbname = result.path[1:]
            host = result.hostname
            port = result.port or 5432
        else:
            # Fallback to individual env vars if DATABASE_URL is not set
            user = os.environ.get("DB_USER")
            password = os.environ.get("DB_PASSWORD")
            dbname = os.environ.get("DB_NAME")
            host = os.environ.get("DB_HOST")
            port = os.environ.get("DB_PORT", 5432)

        if not all([user, password, dbname, host]):
            print("Error: Database connection details are missing.", file=sys.stderr)
            sys.exit(1)

        conn = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        )
        return conn
    except Exception as e:
        print(f"Error: Could not connect to the PostgreSQL database.", file=sys.stderr)
        print(f"Details: {e}", file=sys.stderr)
        sys.exit(1)

def initialize_database():
    """Creates all necessary tables if they don't exist."""
    commands = (
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            password_hash VARCHAR(200) NOT NULL,
            role VARCHAR(20) NOT NULL DEFAULT 'user'
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS whitelisted_ips (
            id SERIAL PRIMARY KEY,
            ip_address VARCHAR(45) UNIQUE NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS settings (
            id SERIAL PRIMARY KEY,
            key VARCHAR(255) UNIQUE NOT NULL,
            value TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS accounts (
            id SERIAL PRIMARY KEY,
            account_name VARCHAR(255) UNIQUE NOT NULL
        );
        """
    )
    
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                for command in commands:
                    cur.execute(command)
            print("Database tables created or already exist.")
    except Exception as e:
        print(f"Error creating tables: {e}", file=sys.stderr)
        sys.exit(1)

def create_admin_user():
    """Creates the default admin user if it doesn't exist."""
    admin_username = 'admin'
    # This is the default password from the original script
    admin_password = 'A9B3nX#Q8k\$mZ6vw'
    hashed_password = generate_password_hash(admin_password, method='pbkdf2:sha256')

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE username = %s", (admin_username,))
                if cur.fetchone():
                    print(f"User '{admin_username}' already exists.")
                else:
                    cur.execute(
                        "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                        (admin_username, hashed_password, 'admin')
                    )
                    print(f"Admin user '{admin_username}' created successfully.")
                    print(f"Username: {admin_username}")
                    print(f"Password: {admin_password}")
    except Exception as e:
        print(f"Error creating admin user: {e}", file=sys.stderr)
        sys.exit(1)

def whitelist_ip(ip_address):
    """Adds the given IP to the whitelist."""
    if not ip_address:
        print("No IP address provided for whitelisting.", file=sys.stderr)
        return

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM whitelisted_ips WHERE ip_address = %s", (ip_address,))
                if cur.fetchone():
                    print(f"IP {ip_address} is already in the whitelist.")
                else:
                    cur.execute("INSERT INTO whitelisted_ips (ip_address) VALUES (%s)", (ip_address,))
                    print(f"IP {ip_address} added to whitelist successfully.")
    except Exception as e:
        print(f"Error whitelisting IP {ip_address}: {e}", file=sys.stderr)

if __name__ == '__main__':
    print("Starting database initialization...")
    
    initialize_database()
    create_admin_user()

    if len(sys.argv) > 1:
        ip_to_whitelist = sys.argv[1]
        print(f"Current IP detected: {ip_to_whitelist}")
        whitelist_ip(ip_to_whitelist)
    else:
        print("No IP address provided as argument. Skipping IP whitelist.", file=sys.stderr)
    
    print("Database initialization complete.")
