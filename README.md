
# M183 BruteForce Project

## Overview
This project demonstrates and analyzes brute-force attacks and modern defense mechanisms on authentication systems in a secure test environment. It is designed for educational purposes, showing both typical attack vectors and effective countermeasures.

**Key Features:**
- Modular attack and defense scripts
- Realistic vulnerable and secure server implementations
- SQLite database with user/account tracking and logging
- Professional code structure, documentation, and best practices

---

## Project Structure

```
attack/
  mono_attack.py         # Simple brute-force (single alphabet)
  poly_attack.py         # Multi-alphabet brute-force (incl. international chars)
  dictionary_attack.py   # Dictionary attack with smart mutations
  parallel_attack.py     # Parallel brute-force (multiprocessing)
  rainbow_attack.py      # Rainbow table attack (lookup file)
  rainbow_table.json     # Precomputed rainbow table (SHA-1)
db/
  schema.sql             # Database schema (users, logging)
  users.sqlite           # SQLite database (auto-generated)
  wordlists/
    common-passwords.txt # Wordlist for dictionary attacks
defense/
  delay.py               # Linear/progressive delay mechanisms
  counter.py             # Account lockout after failed attempts
  captcha.py             # reCAPTCHA v2 integration
  logging.py             # Authentication attempt logging
server/
  vulnerable_server.py   # Insecure demo server (no defenses)
  secure_server.py       # Secure server (all defenses active)
  create_db.py           # Database initialization
README.md                # Project documentation (this file)
```

---

## Attack Implementations

| File                  | Attack Type         | Description |
|-----------------------|--------------------|-------------|
| mono_attack.py        | Mono brute-force   | Tries all passwords from a single alphabet (digits, lower, upper, symbols, or custom) |
| poly_attack.py        | Poly brute-force   | Combines multiple alphabets, incl. Turkish, Hungarian, Cyrillic |
| dictionary_attack.py  | Dictionary attack  | Uses a wordlist (with smart/user-specific entries) and applies common mutations |
| parallel_attack.py    | Parallel brute-force | Splits keyspace across multiple processes (mono/poly/dict modes) |
| rainbow_attack.py     | Rainbow table      | Looks up hashes in a precomputed SHA-1 rainbow table |

**Note:** Each attack is implemented in a separate, clearly assigned file. No hybrid or redundant scripts.

---

## Defense Mechanisms

| File         | Defense Type         | Description |
|--------------|---------------------|-------------|
| delay.py     | Delay (3.1)         | Linear (fixed) and progressive (exponential) delays to slow brute-force |
| counter.py   | Counter/Lockout (3.2) | Locks account after N failed attempts for a set duration |
| captcha.py   | CAPTCHA (3.2)       | Integrates Google reCAPTCHA v2 to block bots |
| logging.py   | Logging (3.3)       | Logs all authentication attempts to DB and file |

All defenses are modular and can be enabled/disabled/configured as needed.

---

## Server Implementations

- **vulnerable_server.py**: Minimal Flask server, no defenses, for attack demonstration.
- **secure_server.py**: Flask server with all defense mechanisms active (delay, lockout, CAPTCHA, logging). Uses bcrypt password hashing with unique salt for each user (defense against rainbow tables).

---

## Database

- SQLite database (`db/users.sqlite`) with schema defined in `db/schema.sql`
- Tracks users, failed attempts, lockout state, and authentication logs
- Wordlist (`db/wordlists/common-passwords.txt`) should include common and user-specific passwords

---

## Setup & Usage Instructions

### 1. Install Requirements

Install Python 3.8+ and required packages:

```sh
pip install flask bcrypt requests
```

### 2. Initialize the Database

Create the database and demo users:

```sh
python server/create_db.py --mode secure
# or for vulnerable mode:
python server/create_db.py --mode vulnerable
```

### 3. Start the Server

**Vulnerable server:**

```sh
python server/vulnerable_server.py
# Runs on http://127.0.0.1:5000
```

**Secure server:**

```sh
python server/secure_server.py
# Runs on http://127.0.0.1:5001
```

### 4. Run Attacks

Each attack script can be run with `--help` for usage instructions. Example:

```sh
python attack/mono_attack.py --target http://127.0.0.1:5000/login --user alice --alphabet digits --max-len 3
python attack/dictionary_attack.py --target http://127.0.0.1:5000/login --user bob --list db/wordlists/common-passwords.txt
python attack/rainbow_attack.py --db db/users.sqlite --table attack/rainbow_table.json
```

### 5. Adjust Defenses

Defense settings can be configured in the respective files in `defense/` or via environment variables (see file headers).

---

## Best Practices & Notes

- All scripts include best-practice headers, docstrings, and error handling
- No passwords or sensitive data are logged
- Modular, testable, and extensible codebase
- For grading: Each requirement is mapped to a single, clearly assigned file

---

## Authors

- Erik Buser (Attacks, Server)
- Cadima Lusiola (Defense, DB)
- Raiyan Mahfuz (Defense, DB)
