import json
import os
import secrets
import getpass
import hashlib

PASSWORD_ITERATIONS = 600_000
PASSWORD_HASH_BYTES = 32

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
RECORDS_FILE = os.path.join(PROJECT_DIR, "password_records.json")

USERNAMES = [
    "Alice",
    "Bob",
    "Charlie",
    "David",
    "Eve",
    "Frank",
    "Grace",
    "Heidi",
    "Ivan",
    "Judy",
]

def hash_password(password, salt):
  return hashlib.pbkdf2_hmac(
  "sha256",
  password.encode("utf-8"),
  salt,
  PASSWORD_ITERATIONS,
  dklen=PASSWORD_HASH_BYTES,
  )

def main():
  if os.path.exists(RECORDS_FILE):
    print("ERROR: password_records.json already exists.")
    print("No existing password records were changed.")
    return
    
  records = {}

  print("Create password records for the demo accounts.")
  print("Passwords will not be displayed or stored in plaintext.\n")

  for username in USERNAMES:
      while True:
          password = getpass.getpass(f"Enter password for {username}: ")
          confirmation = getpass.getpass("Confirm password: ")

          if not password:
              print("Password cannot be empty. Try again.\n")
          elif password != confirmation:
              print("Passwords do not match. Try again.\n")
          else:
              break

      salt = secrets.token_bytes(16)
      password_hash = hash_password(password, salt)

      records[username] = {
          "salt": salt.hex(),
          "password_hash": password_hash.hex(),
          "iterations": PASSWORD_ITERATIONS,
      }

      del password
      del confirmation
      print(f"Password record created for {username}.\n")

  with open(RECORDS_FILE, "x", encoding="utf-8") as file:
      json.dump(records, file, indent=4)

  print("Password records saved successfully.")
  print("File: password_records.json")
  print("No plaintext passwords were saved.")


if __name__ == "__main__":
  main()

