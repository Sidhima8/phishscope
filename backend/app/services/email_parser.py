import email
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr, parsedate_to_datetime
import hashlib
import re
from typing import Dict, Any, List, Optional, Tuple


IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_REGEX = re.compile(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')


class ParsedEmail:
    def __init__(self):
        self.message_id: str = ""
        self.subject: str = ""
        self.from_header: str = ""
        self.from_name: str = ""
        self.from_email: str = ""
        self.from_domain: str = ""
        self.to_recipients: List[str] = []
        self.cc_recipients: List[str] = []
        self.date_str: str = ""
        self.date_parsed: Optional[str] = None
        self.reply_to: str = ""
        self.reply_to_email: str = ""
        self.reply_to_domain: str = ""
        self.return_path: str = ""
        self.return_path_domain: str = ""
        self.raw_headers: str = ""
        self.headers_dict: Dict[str, Any] = {}
        self.received_headers: List[str] = []
        self.received_hops: List[Dict[str, Any]] = []
        self.body_text: str = ""
        self.body_html: str = ""
        self.attachments: List[Dict[str, Any]] = []
        self.mime_structure: Dict[str, Any] = {}
        self.sha256_hash: str = ""
        self.parsing_warnings: List[str] = []


def extract_domain(email_address: str) -> str:
    if not email_address:
        return ""
    if "@" in email_address:
        return email_address.split("@")[-1].strip().lower().rstrip(">")
    return ""


def parse_received_header(header_value: str, hop_index: int) -> Dict[str, Any]:
    """Parse Received: from mail.example.com (1.2.3.4) by mx.google.com with ESMTPS ...; Date"""
    hop = {
        "hop_index": hop_index,
        "raw": header_value.strip(),
        "from_host": "",
        "from_ip": "",
        "by_host": "",
        "protocol": "",
        "date_str": "",
        "is_private_ip": False,
        "suspicious": False,
    }

    # Extract IPs
    ips = IP_REGEX.findall(header_value)
    if ips:
        hop["from_ip"] = ips[0]
        # Check if first octet matches RFC 1918 private / 127
        first_oct = int(ips[0].split(".")[0])
        second_oct = int(ips[0].split(".")[1]) if len(ips[0].split(".")) > 1 else 0
        if first_oct == 10 or (first_oct == 172 and 16 <= second_oct <= 31) or (first_oct == 192 and second_oct == 168) or first_oct == 127:
            hop["is_private_ip"] = True

    # Extract "from host"
    from_match = re.search(r'\bfrom\s+([^\s;]+)', header_value, re.IGNORECASE)
    if from_match:
        hop["from_host"] = from_match.group(1).strip("()[]")

    # Extract "by host"
    by_match = re.search(r'\bby\s+([^\s;]+)', header_value, re.IGNORECASE)
    if by_match:
        hop["by_host"] = by_match.group(1).strip("()[]")

    # Extract timestamp if present after semicolon
    if ";" in header_value:
        hop["date_str"] = header_value.split(";")[-1].strip()

    return hop


def build_mime_tree(part) -> Dict[str, Any]:
    """Recursively build MIME structure representation."""
    content_type = part.get_content_type()
    disposition = part.get_content_disposition()
    filename = part.get_filename() or ""
    
    node = {
        "content_type": content_type,
        "disposition": disposition or "inline",
        "filename": filename,
        "size": len(part.get_payload(decode=True) or b"") if not part.is_multipart() else 0,
        "children": []
    }
    
    if part.is_multipart():
        for subpart in part.get_payload():
            node["children"].append(build_mime_tree(subpart))
            
    return node


def parse_email_message(raw_bytes: bytes) -> ParsedEmail:
    """Safely parse raw email bytes or text into a structured ParsedEmail object."""
    parsed = ParsedEmail()
    parsed.sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception as e:
        # Fallback to standard parser if BytesParser fails
        try:
            msg = email.message_from_bytes(raw_bytes)
            parsed.parsing_warnings.append(f"Used fallback parser: {str(e)}")
        except Exception as e2:
            parsed.parsing_warnings.append(f"Failed to parse email structure: {str(e2)}")
            return parsed

    # Extract standard headers
    parsed.subject = str(msg.get("subject", "") or "").strip()
    parsed.message_id = str(msg.get("message-id", "") or "").strip()
    parsed.from_header = str(msg.get("from", "") or "").strip()
    
    name, addr = parseaddr(parsed.from_header)
    parsed.from_name = name.strip()
    parsed.from_email = addr.strip().lower()
    parsed.from_domain = extract_domain(parsed.from_email)

    # To recipients
    to_header = str(msg.get("to", "") or "")
    if to_header:
        parsed.to_recipients = [addr.strip().lower() for _, addr in email.utils.getaddresses([to_header]) if addr]

    # CC recipients
    cc_header = str(msg.get("cc", "") or "")
    if cc_header:
        parsed.cc_recipients = [addr.strip().lower() for _, addr in email.utils.getaddresses([cc_header]) if addr]

    # Date
    parsed.date_str = str(msg.get("date", "") or "").strip()
    if parsed.date_str:
        try:
            dt = parsedate_to_datetime(parsed.date_str)
            parsed.date_parsed = dt.isoformat()
        except Exception:
            pass

    # Reply-To
    parsed.reply_to = str(msg.get("reply-to", "") or "").strip()
    if parsed.reply_to:
        _, r_addr = parseaddr(parsed.reply_to)
        parsed.reply_to_email = r_addr.strip().lower()
        parsed.reply_to_domain = extract_domain(parsed.reply_to_email)

    # Return-Path
    parsed.return_path = str(msg.get("return-path", "") or "").strip()
    if parsed.return_path:
        _, rp_addr = parseaddr(parsed.return_path)
        parsed.return_path_domain = extract_domain(rp_addr)

    # All headers to text and dictionary
    header_lines = []
    headers_dict = {}
    for key, val in msg.items():
        header_lines.append(f"{key}: {val}")
        k_lower = key.lower()
        if k_lower not in headers_dict:
            headers_dict[k_lower] = val
        elif isinstance(headers_dict[k_lower], list):
            headers_dict[k_lower].append(val)
        else:
            headers_dict[k_lower] = [headers_dict[k_lower], val]

    parsed.raw_headers = "\n".join(header_lines)
    parsed.headers_dict = headers_dict

    # Received headers (order: latest hop first, reversed for chronological delivery)
    received_list = msg.get_all("received", []) or []
    parsed.received_headers = [str(r) for r in received_list]
    for idx, r_val in enumerate(reversed(parsed.received_headers)):
        parsed.received_hops.append(parse_received_header(str(r_val), idx + 1))

    # MIME Structure
    try:
        parsed.mime_structure = build_mime_tree(msg)
    except Exception as e:
        parsed.parsing_warnings.append(f"MIME tree generation error: {str(e)}")

    # Extract Body Parts and Attachments
    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get_content_disposition() or "").lower()
                filename = part.get_filename()

                # Attachment detection
                if filename or content_disposition == "attachment":
                    payload = part.get_payload(decode=True)
                    if payload is not None:
                        f_name = filename or "unnamed_attachment"
                        sha256 = hashlib.sha256(payload).hexdigest()
                        md5 = hashlib.md5(payload).hexdigest()
                        parsed.attachments.append({
                            "filename": f_name,
                            "content_type": content_type,
                            "size_bytes": len(payload),
                            "sha256": sha256,
                            "md5": md5,
                        })
                elif content_type == "text/plain" and not parsed.body_text:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        try:
                            parsed.body_text = payload.decode(charset, errors="replace")
                        except Exception:
                            parsed.body_text = payload.decode("latin-1", errors="replace")
                elif content_type == "text/html" and not parsed.body_html:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        try:
                            parsed.body_html = payload.decode(charset, errors="replace")
                        except Exception:
                            parsed.body_html = payload.decode("latin-1", errors="replace")
        else:
            # Single-part message
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                try:
                    text_content = payload.decode(charset, errors="replace")
                except Exception:
                    text_content = payload.decode("latin-1", errors="replace")
                    
                if content_type == "text/html":
                    parsed.body_html = text_content
                else:
                    parsed.body_text = text_content
    except Exception as e:
        parsed.parsing_warnings.append(f"Body extraction warning: {str(e)}")

    return parsed
