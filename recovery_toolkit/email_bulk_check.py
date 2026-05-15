#!/usr/bin/env python3
"""
Bitcoin Wallet Recovery - Bulk Email Inbox Checker
====================================================
Connects to multiple email accounts via IMAP and searches them for
Blockchain.com related emails (Wallet IDs, login attempts, backups).

USAGE:
  1. Create email_accounts.json with your IMAP credentials (template generated on first run)
  2. python email_bulk_check.py
  3. Review email_recovery_report.txt

WHAT IT FINDS:
  - Wallet IDs (UUIDs) in email bodies from blockchain.com
  - Login attempt notifications (= account is/was active)
  - Subject lines mentioning bitcoin/blockchain/wallet
  - Email attachments named wallet.aes.json or similar
  - Reference to target Bitcoin address 1B8hg...LMcko

SECURITY:
  - Run on YOUR OWN computer
  - Use APP PASSWORDS, not main email password
    Gmail: https://myaccount.google.com/apppasswords
    Yahoo: https://login.yahoo.com/account/security/app-passwords
    Outlook: https://account.microsoft.com/security
  - This tool ONLY READS emails, never sends or modifies
  - Credentials in email_accounts.json never leave your computer
  - DELETE email_accounts.json after recovery is complete

IMAP SETTINGS REFERENCE:
  Gmail:    imap.gmail.com:993        (need app password)
  Yahoo:    imap.mail.yahoo.com:993   (need app password)
  Outlook:  outlook.office365.com:993 (need app password if 2FA)
  iCloud:   imap.mail.me.com:993      (need app password)
  AOL:      imap.aol.com:993
"""

import argparse
import email
import getpass
import imaplib
import json
import os
import re
import ssl
import sys
from email.header import decode_header
from pathlib import Path
from datetime import datetime, timedelta

TARGET_ADDRESS = "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko"

# UUID patterns for Wallet IDs (v4 = Blockchain.com format)
UUID_PATTERN = re.compile(
    r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
)

# Blockchain.com email domains and keywords
BC_DOMAINS = [
    'blockchain.com', 'blockchain.info', 'blockchain-luxembourg.com',
    'no-reply@blockchain', 'support@blockchain', 'noreply@blockchain',
]

BLOCKCHAIN_KEYWORDS = [
    'blockchain.com', 'blockchain wallet', 'wallet id', 'wallet-id',
    'login attempt', 'new device', 'verify your wallet',
    'backup phrase', 'seed phrase', 'recovery phrase',
]

# Common attachment names that might be wallet backups
WALLET_ATTACHMENT_PATTERNS = re.compile(
    r'wallet\.aes\.json|wallet\.json|.*backup.*\.json|.*wallet.*\.json',
    re.IGNORECASE,
)


# IMAP server defaults for common providers
IMAP_DEFAULTS = {
    'gmail.com': ('imap.gmail.com', 993),
    'googlemail.com': ('imap.gmail.com', 993),
    'yahoo.com': ('imap.mail.yahoo.com', 993),
    'yahoo.co.id': ('imap.mail.yahoo.com', 993),
    'ymail.com': ('imap.mail.yahoo.com', 993),
    'outlook.com': ('outlook.office365.com', 993),
    'hotmail.com': ('outlook.office365.com', 993),
    'live.com': ('outlook.office365.com', 993),
    'msn.com': ('outlook.office365.com', 993),
    'icloud.com': ('imap.mail.me.com', 993),
    'me.com': ('imap.mail.me.com', 993),
    'aol.com': ('imap.aol.com', 993),
    'protonmail.com': ('127.0.0.1', 1143),  # needs ProtonMail Bridge running
}


def detect_imap(email_addr):
    """Auto-detect IMAP server from email domain."""
    domain = email_addr.split('@')[-1].lower()
    return IMAP_DEFAULTS.get(domain, (None, None))


def extract_wallet_ids(text):
    """Extract all UUID-format Wallet IDs from text."""
    return list(set(UUID_PATTERN.findall(text)))


def decode_subject(subject_raw):
    """Safely decode email subject."""
    if not subject_raw:
        return ''
    parts = decode_header(subject_raw)
    decoded = []
    for content, charset in parts:
        if isinstance(content, bytes):
            try:
                decoded.append(content.decode(charset or 'utf-8', errors='replace'))
            except Exception:
                decoded.append(content.decode('utf-8', errors='replace'))
        else:
            decoded.append(content)
    return ''.join(decoded)


def get_email_body(msg):
    """Extract plain text body from email message."""
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disposition = str(part.get('Content-Disposition', ''))
            if ctype == 'text/plain' and 'attachment' not in disposition:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        body_parts.append(payload.decode(charset, errors='replace'))
                except Exception:
                    pass
            elif ctype == 'text/html' and 'attachment' not in disposition and not body_parts:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        # Strip basic HTML tags
                        html = payload.decode(charset, errors='replace')
                        text = re.sub(r'<[^>]+>', ' ', html)
                        text = re.sub(r'\s+', ' ', text)
                        body_parts.append(text)
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                body_parts.append(payload.decode(charset, errors='replace'))
        except Exception:
            pass
    return '\n'.join(body_parts)


def get_attachments_info(msg):
    """List attachment filenames in the email."""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            disposition = str(part.get('Content-Disposition', ''))
            if 'attachment' in disposition or 'inline' in disposition:
                filename = part.get_filename()
                if filename:
                    decoded_name = decode_subject(filename)
                    payload = part.get_payload(decode=True)
                    size = len(payload) if payload else 0
                    attachments.append({'name': decoded_name, 'size': size})
    return attachments


def search_account(account_config, output_dir, save_attachments=False):
    """Connect to one IMAP account and search for Blockchain.com emails."""
    email_addr = account_config['email']
    password = account_config['password']
    server = account_config.get('imap_server')
    port = account_config.get('imap_port', 993)

    if not server:
        server, port = detect_imap(email_addr)
        if not server:
            return {'error': f'Unknown provider for {email_addr}, set imap_server manually'}

    print(f"\n{'='*70}")
    print(f"Account: {email_addr}")
    print(f"Server: {server}:{port}")
    print(f"{'='*70}")

    results = {
        'account': email_addr,
        'server': server,
        'wallet_ids': set(),
        'blockchain_emails': [],
        'attachments_found': [],
        'target_address_mentions': [],
        'errors': [],
    }

    try:
        ssl_context = ssl.create_default_context()
        mail = imaplib.IMAP4_SSL(server, port, ssl_context=ssl_context)
        mail.login(email_addr, password)
        print(f"Login OK")
    except imaplib.IMAP4.error as e:
        err = f'Login failed: {e}'
        print(f"  ERROR: {err}")
        results['errors'].append(err)
        return results
    except Exception as e:
        err = f'Connection failed: {e}'
        print(f"  ERROR: {err}")
        results['errors'].append(err)
        return results

    # Get list of folders to search (Inbox + Sent + All Mail + Spam)
    folders_to_search = []
    try:
        status, folder_data = mail.list()
        for line in folder_data:
            if isinstance(line, bytes):
                decoded = line.decode('utf-8', errors='replace')
            else:
                decoded = str(line)
            # Common folder names
            for folder_kw in ['INBOX', 'Sent', 'All Mail', 'Spam', 'Junk', '[Gmail]/All Mail', '[Gmail]/Spam']:
                if folder_kw in decoded:
                    # Extract folder name from IMAP LIST format
                    parts = decoded.split('"')
                    if len(parts) >= 5:
                        folder_name = parts[-2]
                        if folder_name not in folders_to_search:
                            folders_to_search.append(folder_name)
                    elif folder_kw not in folders_to_search:
                        folders_to_search.append(folder_kw)
    except Exception:
        folders_to_search = ['INBOX']

    if not folders_to_search:
        folders_to_search = ['INBOX']

    print(f"  Folders to search: {folders_to_search}")

    # Search each folder
    for folder in folders_to_search:
        try:
            # Quote folder name if it has special chars
            safe_folder = f'"{folder}"' if ' ' in folder or '/' in folder else folder
            status, _ = mail.select(safe_folder, readonly=True)
            if status != 'OK':
                continue
            print(f"\n  Folder: {folder}")
        except Exception as e:
            print(f"  Skip {folder}: {e}")
            continue

        # Search criteria - use OR for multiple senders
        search_queries = [
            'FROM "blockchain.com"',
            'FROM "blockchain.info"',
            'FROM "no-reply@blockchain"',
            'SUBJECT "Wallet ID"',
            'SUBJECT "blockchain"',
            'SUBJECT "wallet"',
            f'BODY "{TARGET_ADDRESS}"',
        ]

        seen_ids = set()
        for query in search_queries:
            try:
                status, msg_ids_data = mail.search(None, query)
                if status != 'OK' or not msg_ids_data or not msg_ids_data[0]:
                    continue
                msg_ids = msg_ids_data[0].split()
                if not msg_ids:
                    continue
                print(f"    Query [{query[:40]}...]: {len(msg_ids)} hits")

                for mid in msg_ids:
                    if mid in seen_ids:
                        continue
                    seen_ids.add(mid)

                    try:
                        status, msg_data = mail.fetch(mid, '(RFC822)')
                        if status != 'OK':
                            continue
                        raw = msg_data[0][1]
                        msg = email.message_from_bytes(raw)

                        subject = decode_subject(msg.get('Subject', ''))
                        from_addr = decode_subject(msg.get('From', ''))
                        date_str = msg.get('Date', '')
                        body = get_email_body(msg)
                        full_text = f"{subject}\n{from_addr}\n{body}"

                        # Extract Wallet IDs
                        ids_in_email = extract_wallet_ids(full_text)
                        is_from_bc = any(d.lower() in from_addr.lower() for d in BC_DOMAINS)

                        # Only count Wallet IDs from emails sent BY Blockchain.com
                        if is_from_bc and ids_in_email:
                            for wid in ids_in_email:
                                results['wallet_ids'].add(wid)

                        # Check for target address
                        if TARGET_ADDRESS in full_text:
                            results['target_address_mentions'].append({
                                'subject': subject,
                                'from': from_addr,
                                'date': date_str,
                                'folder': folder,
                            })

                        # Check attachments
                        attachments = get_attachments_info(msg)
                        for att in attachments:
                            if WALLET_ATTACHMENT_PATTERNS.search(att['name']):
                                results['attachments_found'].append({
                                    'subject': subject,
                                    'from': from_addr,
                                    'date': date_str,
                                    'attachment_name': att['name'],
                                    'attachment_size': att['size'],
                                    'folder': folder,
                                })

                                # Optionally save attachment
                                if save_attachments:
                                    save_path = output_dir / 'attachments' / safe_filename(
                                        f"{email_addr}_{att['name']}"
                                    )
                                    save_path.parent.mkdir(parents=True, exist_ok=True)
                                    for part in msg.walk():
                                        if part.get_filename() == att['name']:
                                            payload = part.get_payload(decode=True)
                                            if payload:
                                                save_path.write_bytes(payload)
                                                print(f"      Saved: {save_path}")

                        # Always log Blockchain emails
                        if is_from_bc or any(kw in subject.lower() for kw in ['blockchain', 'wallet']):
                            results['blockchain_emails'].append({
                                'subject': subject[:100],
                                'from': from_addr[:60],
                                'date': date_str,
                                'wallet_ids_in_body': ids_in_email if is_from_bc else [],
                                'folder': folder,
                            })

                    except Exception as e:
                        results['errors'].append(f'Parse error: {e}')

            except imaplib.IMAP4.error as e:
                # Some servers reject some queries
                continue
            except Exception as e:
                results['errors'].append(f'Search error in {folder} [{query}]: {e}')

    try:
        mail.close()
        mail.logout()
    except Exception:
        pass

    return results


def safe_filename(name):
    """Make a filename safe for filesystem."""
    return re.sub(r'[^a-zA-Z0-9._-]', '_', name)


def write_report(all_results, report_path):
    """Write consolidated report to file."""
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("EMAIL BULK RECOVERY REPORT\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write(f"Target Bitcoin Address: {TARGET_ADDRESS}\n")
        f.write("=" * 70 + "\n\n")

        all_wallet_ids = set()
        all_attachments = []
        all_target_mentions = []

        for r in all_results:
            f.write(f"\n--- ACCOUNT: {r['account']} ---\n")
            if r.get('errors'):
                f.write("Errors:\n")
                for e in r['errors'][:5]:
                    f.write(f"  {e}\n")

            wids = sorted(r['wallet_ids'])
            f.write(f"Wallet IDs found (from blockchain.com emails): {len(wids)}\n")
            for wid in wids:
                f.write(f"  {wid}\n")
                all_wallet_ids.add(wid)

            f.write(f"Blockchain.com related emails: {len(r['blockchain_emails'])}\n")
            for e in r['blockchain_emails'][:30]:
                f.write(f"  [{e['date'][:25]}] {e['from']}\n")
                f.write(f"    Subject: {e['subject']}\n")
                if e.get('wallet_ids_in_body'):
                    for wid in e['wallet_ids_in_body']:
                        f.write(f"    Wallet ID: {wid}\n")

            if r['attachments_found']:
                f.write(f"\nWallet ATTACHMENTS in this account: {len(r['attachments_found'])}\n")
                for a in r['attachments_found']:
                    f.write(f"  [{a['date'][:25]}] {a['attachment_name']} ({a['attachment_size']} bytes)\n")
                    f.write(f"    Subject: {a['subject']}\n")
                    f.write(f"    From: {a['from']}\n")
                    all_attachments.append({**a, 'account': r['account']})

            if r['target_address_mentions']:
                f.write(f"\n*** TARGET ADDRESS MENTIONED in this account ***\n")
                for m in r['target_address_mentions']:
                    f.write(f"  [{m['date'][:25]}] Subject: {m['subject']}\n")
                    f.write(f"    From: {m['from']} | Folder: {m['folder']}\n")
                    all_target_mentions.append({**m, 'account': r['account']})

        f.write("\n\n" + "=" * 70 + "\n")
        f.write("FINAL SUMMARY\n")
        f.write("=" * 70 + "\n")
        f.write(f"Total accounts scanned: {len(all_results)}\n")
        f.write(f"Total unique Wallet IDs from blockchain.com: {len(all_wallet_ids)}\n")
        f.write(f"Total wallet attachment files found: {len(all_attachments)}\n")
        f.write(f"Total target address mentions: {len(all_target_mentions)}\n\n")

        if all_wallet_ids:
            f.write("ALL WALLET IDs (try login at https://login.blockchain.com):\n")
            for wid in sorted(all_wallet_ids):
                f.write(f"  {wid}\n")

        if all_target_mentions:
            f.write("\n*** TARGET ADDRESS FOUND IN EMAIL — INVESTIGATE THESE ***\n")
            for m in all_target_mentions:
                f.write(f"  Account: {m['account']}\n")
                f.write(f"  Date: {m['date']}\n")
                f.write(f"  Subject: {m['subject']}\n")
                f.write(f"  From: {m['from']}\n\n")


def create_template(path):
    """Create a template config file."""
    template = [
        {
            "email": "your_email_1@gmail.com",
            "password": "app_password_here_NOT_main_password",
            "imap_server": "auto",
            "imap_port": 993,
            "_comment": "For Gmail: get App Password at https://myaccount.google.com/apppasswords"
        },
        {
            "email": "your_email_2@yahoo.com",
            "password": "app_password_here",
            "imap_server": "auto",
            "imap_port": 993,
            "_comment": "For Yahoo: get App Password at https://login.yahoo.com/account/security/app-passwords"
        }
    ]
    Path(path).write_text(json.dumps(template, indent=2))
    print(f"Template config created: {path}")
    print()
    print("Next steps:")
    print(f"  1. Edit {path} with your real email accounts and APP PASSWORDS")
    print("  2. Use APP PASSWORDS, not your main email password!")
    print("  3. Run: python email_bulk_check.py")
    print("  4. Delete email_accounts.json after recovery is complete")


def main():
    parser = argparse.ArgumentParser(
        description="Bulk check email inboxes for Blockchain.com Wallet IDs and backups",
    )
    parser.add_argument(
        "--config",
        default="email_accounts.json",
        help="JSON config file with email accounts (default: email_accounts.json)",
    )
    parser.add_argument(
        "--output",
        default="email_recovery_report.txt",
        help="Output report file",
    )
    parser.add_argument(
        "--save-attachments",
        action="store_true",
        help="Save wallet attachment files to ./attachments/",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Create a template config file and exit",
    )
    args = parser.parse_args()

    config_path = Path(args.config)

    if args.init or not config_path.exists():
        if not config_path.exists():
            print(f"Config file not found: {config_path}")
            print("Creating template...")
        create_template(config_path)
        sys.exit(0)

    with open(config_path) as f:
        accounts = json.load(f)

    if not isinstance(accounts, list):
        print("Config must be a JSON array of account objects")
        sys.exit(1)

    print(f"Loaded {len(accounts)} email account(s) from {config_path}")
    print()
    print("WARNING: This tool will connect to your email accounts via IMAP.")
    print("Make sure you are using APP PASSWORDS, not main email passwords.")
    print("Run on YOUR OWN computer, offline-ish (only IMAP traffic to email servers).")
    print()

    output_dir = Path(args.output).parent
    if args.save_attachments:
        (output_dir / 'attachments').mkdir(parents=True, exist_ok=True)

    all_results = []
    for i, account in enumerate(accounts):
        if not account.get('email') or not account.get('password'):
            print(f"Skipping account {i}: missing email or password")
            continue
        if 'app_password_here' in account.get('password', '').lower():
            print(f"Skipping account {i}: still has placeholder password")
            continue
        if account.get('imap_server') == 'auto':
            account['imap_server'] = None
        result = search_account(account, output_dir, args.save_attachments)
        all_results.append(result)

    write_report(all_results, args.output)

    print(f"\n{'='*70}")
    print(f"REPORT WRITTEN: {Path(args.output).resolve()}")
    print(f"{'='*70}")
    print()
    print("REMINDER: Delete email_accounts.json (contains passwords) after recovery!")


if __name__ == "__main__":
    main()
