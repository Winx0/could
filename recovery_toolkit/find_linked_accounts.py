#!/usr/bin/env python3
"""
Find Linked Email Accounts Tool
================================
Scans your primary email's inbox via IMAP to discover all OTHER email
accounts you've linked it to as recovery email.

Specifically searches for:
  - Google/Gmail account creation confirmations
  - Login alerts from Google ("New sign-in to your Google Account")
  - Security alerts that mention Gmail addresses
  - Blockchain.com sign-up confirmations
  - GitHub, Discord, exchange notifications

USAGE:
  python find_linked_accounts.py
  Then enter your Yahoo/Outlook email + APP password when prompted.

OUTPUT:
  linked_accounts_report.txt - all email addresses + wallet IDs discovered

SECURITY:
  - Use APP PASSWORD only, not main password
  - Yahoo: https://login.yahoo.com/account/security/app-passwords
  - Read-only IMAP search, doesn't modify mail
"""
import argparse
import email
import getpass
import imaplib
import re
import ssl
import sys
from collections import defaultdict
from email.header import decode_header
from pathlib import Path

GMAIL_PATTERN = re.compile(
    r'\b([a-zA-Z0-9._+\-]+)@gmail\.com\b',
    re.IGNORECASE,
)
ANY_EMAIL_PATTERN = re.compile(
    r'\b([a-zA-Z0-9._+\-]+)@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b',
)
UUID_V4_PATTERN = re.compile(
    r'\b[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b',
    re.IGNORECASE,
)

GOOGLE_SENDERS = [
    'no-reply@accounts.google.com',
    'googlecommunityteam-noreply@google.com',
    'no-reply@google.com',
    'security-noreply@google.com',
]

EXCHANGE_DOMAINS = [
    'binance.com', 'coinbase.com', 'kraken.com', 'bitfinex.com',
    'huobi.com', 'gemini.com', 'kucoin.com', 'okx.com',
    'indodax.com', 'tokocrypto.com', 'pintu.co.id',
]

SEARCH_QUERIES = [
    'FROM "accounts.google.com"',
    'FROM "google.com"',
    'SUBJECT "Google Account"',
    'SUBJECT "Welcome to Gmail"',
    'SUBJECT "verify your email"',
    'SUBJECT "Critical security alert"',
    'SUBJECT "New sign-in"',
    'SUBJECT "Security alert"',
    'SUBJECT "linked"',
    'FROM "blockchain.com"',
    'SUBJECT "Wallet ID"',
    'SUBJECT "wallet"',
    'FROM "noreply@github.com"',
    'FROM "no-reply@discord.com"',
    'FROM "binance.com"',
    'FROM "coinbase.com"',
    'FROM "indodax.com"',
    'FROM "tokocrypto.com"',
]

IMAP_DEFAULTS = {
    'gmail.com': ('imap.gmail.com', 993),
    'yahoo.com': ('imap.mail.yahoo.com', 993),
    'yahoo.co.id': ('imap.mail.yahoo.com', 993),
    'ymail.com': ('imap.mail.yahoo.com', 993),
    'outlook.com': ('outlook.office365.com', 993),
    'hotmail.com': ('outlook.office365.com', 993),
    'live.com': ('outlook.office365.com', 993),
    'icloud.com': ('imap.mail.me.com', 993),
    'me.com': ('imap.mail.me.com', 993),
    'aol.com': ('imap.aol.com', 993),
}


def detect_imap(email_addr):
    domain = email_addr.split('@')[-1].lower()
    return IMAP_DEFAULTS.get(domain, (None, None))


def decode_subject(raw):
    if not raw:
        return ''
    parts = decode_header(raw)
    out = []
    for content, charset in parts:
        if isinstance(content, bytes):
            try:
                out.append(content.decode(charset or 'utf-8', errors='replace'))
            except Exception:
                out.append(content.decode('utf-8', errors='replace'))
        else:
            out.append(content)
    return ''.join(out)


def get_body(msg):
    parts = []
    if msg.is_multipart():
        for p in msg.walk():
            ct = p.get_content_type()
            disp = str(p.get('Content-Disposition', ''))
            if ct in ('text/plain', 'text/html') and 'attachment' not in disp:
                try:
                    payload = p.get_payload(decode=True)
                    if payload:
                        charset = p.get_content_charset() or 'utf-8'
                        text = payload.decode(charset, errors='replace')
                        if ct == 'text/html':
                            text = re.sub(r'<[^>]+>', ' ', text)
                            text = re.sub(r'\s+', ' ', text)
                        parts.append(text)
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                parts.append(payload.decode(charset, errors='replace'))
        except Exception:
            pass
    return '\n'.join(parts)


def main():
    parser = argparse.ArgumentParser(description="Find linked email accounts via IMAP")
    parser.add_argument("--email", help="Your primary email address")
    parser.add_argument("--server", help="IMAP server (auto-detect if not given)")
    parser.add_argument("--port", type=int, default=993)
    parser.add_argument("--output", default="linked_accounts_report.txt")
    args = parser.parse_args()

    print("=" * 70)
    print("FIND LINKED EMAIL ACCOUNTS")
    print("=" * 70)
    print()

    if args.email:
        email_addr = args.email
    else:
        email_addr = input("Your primary email: ").strip()

    if args.server:
        server = args.server
        port = args.port
    else:
        server, port = detect_imap(email_addr)
        if not server:
            print(f"Auto-detect failed for {email_addr}, please specify --server")
            sys.exit(1)

    print(f"Server: {server}:{port}")
    print()
    print("IMPORTANT: Use APP PASSWORD, not your main password!")
    print(f"  Yahoo: https://login.yahoo.com/account/security/app-passwords")
    print(f"  Gmail: https://myaccount.google.com/apppasswords")
    print()
    password = getpass.getpass("App password (hidden): ")
    # Yahoo & Gmail App Passwords use spaces for readability (e.g. "abcd efgh ijkl mnop")
    # but IMAP LOGIN doesn't accept spaces. Strip them.
    password = password.replace(' ', '').replace('\t', '').strip()
    if len(password) < 8:
        print(f"WARNING: Password is only {len(password)} chars after stripping. App passwords are usually 16 chars.")

    print(f"\nConnecting to {server}...")
    try:
        ssl_context = ssl.create_default_context()
        mail = imaplib.IMAP4_SSL(server, port, ssl_context=ssl_context)
        mail.login(email_addr, password)
        print(f"Login OK")
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    folders = ['INBOX']
    try:
        status, data = mail.list()
        for line in data:
            decoded = line.decode('utf-8', errors='replace') if isinstance(line, bytes) else str(line)
            for kw in ['Sent', 'All Mail', 'Spam', 'Junk', 'Bulk Mail', 'Trash']:
                if kw in decoded:
                    parts = decoded.split('"')
                    if len(parts) >= 5:
                        fn = parts[-2]
                        if fn not in folders:
                            folders.append(fn)
    except Exception:
        pass

    print(f"Folders: {folders}")
    print()

    found_gmail = defaultdict(set)
    found_other_emails = defaultdict(set)
    found_exchanges = set()
    google_emails_count = 0
    blockchain_emails_count = 0
    wallet_ids = set()
    seen_msg_ids = set()

    # Skip these (no-reply addresses, not user accounts)
    SKIP_PREFIXES = ('no-reply', 'noreply', 'support', 'info', 'security',
                     'service', 'donotreply', 'help', 'admin', 'team',
                     'notifications', 'marketing', 'newsletter', 'mailer')

    for folder in folders:
        safe = f'"{folder}"' if ' ' in folder or '/' in folder else folder
        try:
            status, _ = mail.select(safe, readonly=True)
            if status != 'OK':
                continue
            print(f"\nScanning: {folder}")
        except Exception:
            continue

        for query in SEARCH_QUERIES:
            try:
                status, data = mail.search(None, query)
                if status != 'OK' or not data or not data[0]:
                    continue
                msg_ids = data[0].split()
                if not msg_ids:
                    continue
                print(f"  [{query[:40]:40s}] {len(msg_ids)} hits")

                for mid in msg_ids:
                    if mid in seen_msg_ids:
                        continue
                    seen_msg_ids.add(mid)

                    try:
                        status, msg_data = mail.fetch(mid, '(RFC822)')
                        if status != 'OK':
                            continue
                        msg = email.message_from_bytes(msg_data[0][1])

                        from_addr = decode_subject(msg.get('From', ''))
                        to_addr = decode_subject(msg.get('To', ''))
                        subject = decode_subject(msg.get('Subject', ''))
                        body = get_body(msg)

                        is_google = any(s in from_addr.lower() for s in GOOGLE_SENDERS)
                        is_blockchain = 'blockchain.com' in from_addr.lower()

                        if is_google:
                            google_emails_count += 1
                        if is_blockchain:
                            blockchain_emails_count += 1

                        # Check for exchanges
                        for ex in EXCHANGE_DOMAINS:
                            if ex in from_addr.lower():
                                found_exchanges.add(ex)

                        full_text = f"{from_addr}\n{to_addr}\n{subject}\n{body}"

                        # Find Gmail addresses
                        for m in GMAIL_PATTERN.finditer(full_text):
                            gmail_addr = m.group(0).lower()
                            local_part = gmail_addr.split('@')[0]
                            if local_part.startswith(SKIP_PREFIXES):
                                continue
                            if len(local_part) < 3:
                                continue
                            found_gmail[gmail_addr].add(subject[:80])

                        # Wallet IDs from blockchain emails only
                        if is_blockchain:
                            for m in UUID_V4_PATTERN.finditer(full_text):
                                wallet_ids.add(m.group(0).lower())

                    except Exception:
                        pass
            except imaplib.IMAP4.error:
                continue
            except Exception:
                continue

    try:
        mail.close()
        mail.logout()
    except Exception:
        pass

    # Write report
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(f"# Linked Accounts Report for {email_addr}\n")
        import datetime
        f.write(f"# Generated: {datetime.datetime.now().isoformat()}\n\n")
        f.write(f"Google emails received: {google_emails_count}\n")
        f.write(f"Blockchain.com emails received: {blockchain_emails_count}\n")
        f.write(f"Unique Gmail addresses found: {len(found_gmail)}\n")
        f.write(f"Confirmed Wallet IDs: {len(wallet_ids)}\n")
        f.write(f"Crypto exchanges with account: {len(found_exchanges)}\n\n")

        f.write("=" * 70 + "\n")
        f.write("GMAIL ADDRESSES (linked to your primary email):\n")
        f.write("=" * 70 + "\n")
        for gmail in sorted(found_gmail):
            subjects = list(found_gmail[gmail])[:3]
            f.write(f"\n{gmail}\n")
            for s in subjects:
                f.write(f"  - {s}\n")

        if found_exchanges:
            f.write("\n" + "=" * 70 + "\n")
            f.write("CRYPTO EXCHANGES (your accounts):\n")
            f.write("=" * 70 + "\n")
            for ex in sorted(found_exchanges):
                f.write(f"  {ex}\n")

        if wallet_ids:
            f.write("\n" + "=" * 70 + "\n")
            f.write("VERIFIED BLOCKCHAIN.COM WALLET IDs:\n")
            f.write("=" * 70 + "\n")
            for wid in sorted(wallet_ids):
                f.write(f"  {wid}\n")

    print()
    print("=" * 70)
    print("DONE")
    print("=" * 70)
    print(f"Google emails received: {google_emails_count}")
    print(f"Blockchain emails received: {blockchain_emails_count}")
    print(f"Unique Gmail addresses found: {len(found_gmail)}")
    print(f"Wallet IDs found: {len(wallet_ids)}")
    print(f"Crypto exchanges: {len(found_exchanges)}")
    print()
    print(f"Report: {Path(args.output).resolve()}")
    print()

    if found_gmail:
        print(f"Sample Gmail accounts (first 20):")
        for g in sorted(found_gmail)[:20]:
            print(f"  {g}")
    if found_exchanges:
        print(f"\nCrypto exchanges with account:")
        for ex in sorted(found_exchanges):
            print(f"  {ex}")
    if wallet_ids:
        print()
        print("CONFIRMED Wallet IDs from blockchain.com emails:")
        for w in sorted(wallet_ids):
            print(f"  {w}")
        print()
        print("Try login at: https://login.blockchain.com")


if __name__ == "__main__":
    main()
