
import os
import sys
import psycopg2

def add_ip_to_whitelist(ip_address):
    """Adds a given IP address to the whitelist in the database."""
    try:
        conn = psycopg2.connect(
            host=os.environ.get("DB_HOST", "localhost"),
            database=os.environ.get("DB_NAME", "gbot_web_app"),
            user=os.environ.get("DB_USER", "user"),
            password=os.environ.get("DB_PASSWORD", "password")
        )
        cur = conn.cursor()

        # Use the correct table name 'whitelisted_ips'
        cur.execute("SELECT ip_address FROM whitelisted_ips WHERE ip_address = %s", (ip_address,))
        
        if cur.fetchone():
            print(f"IP {ip_address} is already in the whitelist.")
        else:
            cur.execute("INSERT INTO whitelisted_ips (ip_address) VALUES (%s)", (ip_address,))
            conn.commit()
            print(f"IP {ip_address} added to whitelist successfully.")

        cur.close()
        conn.close()

    except psycopg2.OperationalError as e:
        print(f"Database connection error: {e}", file=sys.stderr)
        print("Please ensure your database is running and the environment variables are set.", file=sys.stderr)
        sys.exit(1)
    except psycopg2.errors.UndefinedTable:
        print("Error: The table 'whitelisted_ips' was not found.", file=sys.stderr)
        print("Please check the database schema. The setup may not have completed.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python manage_whitelist.py <IP_ADDRESS>", file=sys.stderr)
        sys.exit(1)
    
    current_ip = sys.argv[1]
    print(f"Attempting to whitelist current IP: {current_ip}")
    add_ip_to_whitelist(current_ip)
