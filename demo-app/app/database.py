"""
Database setup for SecureBank demo application.
Uses SQLite for simplicity in the demo.
"""
import sqlite3
import os
import bcrypt

DB_PATH = os.environ.get(
    "SECUREBANK_TEST_DB",
    os.path.join(os.path.dirname(__file__), "..", "securebank.db"),
)


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            full_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Accounts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            account_number TEXT UNIQUE NOT NULL,
            account_type TEXT DEFAULT 'checking',
            balance REAL DEFAULT 0.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Transactions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            transaction_type TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        )
    """)

    # Profiles table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            phone TEXT,
            address TEXT,
            ssn_last4 TEXT,
            date_of_birth TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    _seed_demo_data(conn)
    conn.close()


def _seed_demo_data(conn):
    cursor = conn.cursor()

    # Check if already seeded
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    if count > 0:
        return

    # Seed users
    users = [
        ("alice", "alice@securebank.demo", hash_password("alice123"), "Alice Johnson"),
        ("bob", "bob@securebank.demo", hash_password("bob123"), "Bob Smith"),
        ("carol", "carol@securebank.demo", hash_password("carol123"), "Carol Williams"),
    ]

    cursor.executemany(
        "INSERT INTO users (username, email, hashed_password, full_name) VALUES (?, ?, ?, ?)",
        users,
    )

    # Seed accounts
    accounts = [
        (1, "ACC-1001", "checking", 5420.75),
        (2, "ACC-1002", "checking", 12800.50),
        (2, "ACC-1003", "savings", 45000.00),
        (3, "ACC-1004", "checking", 2300.00),
    ]

    cursor.executemany(
        "INSERT INTO accounts (user_id, account_number, account_type, balance) VALUES (?, ?, ?, ?)",
        accounts,
    )

    # Seed transactions
    transactions = [
        (1, "credit", 1000.00, "Salary deposit"),
        (1, "debit", 250.00, "Rent payment"),
        (2, "credit", 5000.00, "Business income"),
        (2, "debit", 1200.00, "Mortgage payment"),
        (3, "credit", 50000.00, "Savings transfer"),
        (4, "credit", 3000.00, "Salary deposit"),
    ]

    cursor.executemany(
        "INSERT INTO transactions (account_id, transaction_type, amount, description) VALUES (?, ?, ?, ?)",
        transactions,
    )

    # Seed profiles
    profiles = [
        (1, "+1-555-0101", "123 Oak Street, Springfield", "6789", "1990-03-15"),
        (2, "+1-555-0102", "456 Maple Ave, Shelbyville", "4321", "1985-07-22"),
        (3, "+1-555-0103", "789 Pine Road, Capital City", "8765", "1992-11-08"),
    ]

    cursor.executemany(
        "INSERT INTO profiles (user_id, phone, address, ssn_last4, date_of_birth) VALUES (?, ?, ?, ?, ?)",
        profiles,
    )

    conn.commit()
