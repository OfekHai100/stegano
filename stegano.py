#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import struct
import hashlib
import zlib
import logging
import sys
from collections import namedtuple

# Constants
PADDING = 6  # Padding in pixels to subtract from resized width and height


# Configure logging
logging.basicConfig(
    filename='dudik.log',
    level=logging.DEBUG,
    format='[%(asctime)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger()

# Metadata constants
METADATA_FORMAT = '<4sBQQ16s'
METADATA_SIZE = struct.calcsize(METADATA_FORMAT)
METADATA_MAGIC = b'DUDK'

# Namedtuple for PNG IHDR
PngHeader = namedtuple('PngHeader', [
    'width', 'height', 'bit_depth', 'color_type',
    'compression', 'filter_method', 'interlace'
])

def paeth_predictor(a, b, c):
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    elif pb <= pc:
        return b
    else:
        return c

def apply_filters(pixel_data, width, height, channels):
    """Apply PNG filters to raw pixel data"""
    stride = width * channels
    filtered = bytearray()
    prev_row = bytearray(stride)
    
    for y in range(height):
        # Use filter type 0 (None) for simplicity
        filtered.append(0)
        
        # Get current row pixels
        row_start = y * stride
        row_end = row_start + stride
        row_data = pixel_data[row_start:row_end]
        
        # Apply filter (none in this case)
        filtered.extend(row_data)
        
        # Store for next row
        prev_row = row_data
    
    return bytes(filtered)

def reverse_filters(filtered_data, width, height, channels):
    """Reverse PNG filters to get raw pixel data"""
    stride = width * channels
    pixel_data = bytearray()
    prev_row = bytearray(stride)
    
    offset = 0
    for y in range(height):
        filter_type = filtered_data[offset]
        offset += 1
        
        # Get current row data
        row_data = filtered_data[offset:offset+stride]
        offset += stride
        
        # Reverse filter based on type
        if filter_type == 0:  # None
            pixel_data.extend(row_data)
        elif filter_type == 1:  # Sub
            row = bytearray()
            for x in range(stride):
                left = row[x - channels] if x >= channels else 0
                val = (row_data[x] + left) % 256
                row.append(val)
            pixel_data.extend(row)
        elif filter_type == 2:  # Up
            row = bytearray()
            for x in range(stride):
                val = (row_data[x] + prev_row[x]) % 256
                row.append(val)
            pixel_data.extend(row)
        elif filter_type == 3:  # Average
            row = bytearray()
            for x in range(stride):
                left = row[x - channels] if x >= channels else 0
                up = prev_row[x]
                val = (row_data[x] + (left + up) // 2) % 256
                row.append(val)
            pixel_data.extend(row)
        elif filter_type == 4:  # Paeth
            row = bytearray()
            for x in range(stride):
                left = row[x - channels] if x >= channels else 0
                up = prev_row[x]
                upper_left = prev_row[x - channels] if x >= channels else 0
                val = (row_data[x] + paeth_predictor(left, up, upper_left)) % 256
                row.append(val)
        else:
            raise ValueError(f"Unknown filter type: {filter_type}")
        
        # Store for next row
        prev_row = pixel_data[-stride:]
    
    return bytes(pixel_data)

def read_png_header(file_path):
    """Read and parse the PNG IHDR chunk."""
    with open(file_path, 'rb') as f:
        sig = f.read(8)
        if sig != b'\x89PNG\r\n\x1a\n':
            raise ValueError("Not a PNG file")
        length, ctype = struct.unpack('>I4s', f.read(8))
        if ctype != b'IHDR':
            raise ValueError("IHDR chunk not found")
        data = f.read(length)
        f.read(4)  # skip CRC
        w, h, bd, ct, comp, filt, inter = struct.unpack('>IIBBBBB', data)
        return PngHeader(w, h, bd, ct, comp, filt, inter)

def validate_png_for_stego(header):
    """Ensure PNG is 8-bit truecolor or truecolor+alpha, no interlace."""
    if header.bit_depth != 8:
        raise ValueError("Only 8-bit PNG supported")
    if header.color_type not in (2, 6):
        raise ValueError("Only RGB (2) or RGBA (6) PNG supported")
    if header.compression != 0 or header.filter_method != 0 or header.interlace != 0:
        raise ValueError("Unsupported PNG compression/filter/interlace")
    return True

def embed_bits(source_bytes, payload_bytes, lsb):
    """LSB-embed payload_bytes into source_bytes, return new bytes."""
    src = bytearray(source_bytes)
    pay = bytearray(payload_bytes)
    bit_idx = 0
    total_bits = len(pay) * 8
    for i in range(len(src)):
        if bit_idx >= total_bits:
            break
        for bit_pos in range(lsb):
            if bit_idx >= total_bits:
                break
            bidx = bit_idx // 8
            bbit = bit_idx % 8
            bit_val = (pay[bidx] >> bbit) & 1
            src[i] = (src[i] & ~(1 << bit_pos)) | (bit_val << bit_pos)
            bit_idx += 1
    return bytes(src)

def extract_bits(source_bytes, lsb, payload_length):
    """Extract payload_length bytes from source_bytes via LSB steganography."""
    payload = bytearray(payload_length)
    bit_idx = 0
    total_bits = payload_length * 8
    for b in source_bytes:
        if bit_idx >= total_bits:
            break
        for bit_pos in range(lsb):
            if bit_idx >= total_bits:
                break
            bit_val = (b >> bit_pos) & 1
            tgt_byte = bit_idx // 8
            tgt_bit = bit_idx % 8
            if bit_val:
                payload[tgt_byte] |= (1 << tgt_bit)
            bit_idx += 1
    return bytes(payload)

def calculate_file_md5(path):
    """Return raw 16-byte MD5 of file."""
    h = hashlib.md5()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.digest()

def read_png_data(png_path):
    """Read PNG file and return all chunks with IDAT combined."""
    with open(png_path, 'rb') as f:
        # Read signature
        signature = f.read(8)
        if signature != b'\x89PNG\r\n\x1a\n':
            raise ValueError("Invalid PNG signature")
        
        chunks = []
        idat_data = bytearray()
        
        while True:
            chunk_header = f.read(8)
            if not chunk_header:
                break
                
            length, chunk_type = struct.unpack('>I4s', chunk_header)
            chunk_data = f.read(length)
            crc = f.read(4)
            
            if chunk_type == b'IDAT':
                idat_data.extend(chunk_data)
            else:
                # Save previous IDAT chunks if any
                if idat_data:
                    chunks.append((b'IDAT', bytes(idat_data), None))
                    idat_data = bytearray()
                chunks.append((chunk_type, chunk_data, crc))
        
        # Save last IDAT chunk if exists
        if idat_data:
            chunks.append((b'IDAT', bytes(idat_data), None))
    
    return signature, chunks

def write_png_data(output_path, signature, chunks):
    """Write PNG file from signature and chunks."""
    with open(output_path, 'wb') as f:
        f.write(signature)
        
        for chunk_type, chunk_data, crc in chunks:
            # Write chunk header
            f.write(struct.pack('>I4s', len(chunk_data), chunk_type))
            f.write(chunk_data)
            
            # Calculate CRC if not provided
            if crc is None:
                crc = zlib.crc32(chunk_type + chunk_data) & 0xffffffff
                f.write(struct.pack('>I', crc))
            else:
                f.write(crc)

def process_png_pixels(png_path):
    """Process PNG image and return raw pixel data."""
    _, chunks = read_png_data(png_path)
    
    # Find IDAT chunks
    idat_data = bytearray()
    for chunk_type, chunk_data, _ in chunks:
        if chunk_type == b'IDAT':
            idat_data.extend(chunk_data)
    
    if not idat_data:
        raise ValueError("No IDAT data found in PNG")
    
    # Decompress pixel data
    try:
        decompressed = zlib.decompress(bytes(idat_data))
    except zlib.error as e:
        raise ValueError(f"Decompression failed: {str(e)}")
    
    # Read header for dimensions
    hdr = read_png_header(png_path)
    w, h = hdr.width, hdr.height
    channels = 3 if hdr.color_type == 2 else 4
    
    # Reverse PNG filters to get raw pixel data
    pixel_data = reverse_filters(decompressed, w, h, channels)
    
    return hdr, pixel_data

def create_png_data(hdr, pixel_data):
    """Create PNG data from raw pixel data."""
    w, h = hdr.width, hdr.height
    channels = 3 if hdr.color_type == 2 else 4
    
    # Apply PNG filters to raw pixel data
    filtered_data = apply_filters(pixel_data, w, h, channels)
    
    # Compress the data
    compressor = zlib.compressobj()
    compressed = compressor.compress(filtered_data)
    compressed += compressor.flush()
    
    return compressed

import math
def resize_pixel_data(pixel_data: bytes, orig_w: int, orig_h: int, channels: int,
                      new_w: int, new_h: int) -> bytes:
    """Nearest-neighbor resize of raw pixel data."""
    new_data = bytearray(new_w * new_h * channels)
    for y in range(new_h):
        oy = int(y * orig_h / new_h)
        for x in range(new_w):
            ox = int(x * orig_w / new_w)
            ni = (y * new_w + x) * channels
            oi = (oy * orig_w + ox) * channels
            new_data[ni:ni+channels] = pixel_data[oi:oi+channels]
    return bytes(new_data)

import math
import time
def inject_payload(png_path: str, payload_path: str, lsb: int, output_prefix: str, max_mb=None):
    """Embed payload across resized PNGs so each output ≤ max_mb (if set)."""
    PADDING = 6  # Padding in pixels to subtract from width/height

    # Read cover and payload
    hdr0 = read_png_header(png_path)
    validate_png_for_stego(hdr0)
    channels = 3 if hdr0.color_type == 2 else 4
    payload_size = os.path.getsize(payload_path)
    total_bits = payload_size * 8
    metadata_bits = METADATA_SIZE * 8

    # Determine max raw capacity (in bytes)
    if max_mb is None:
        max_raw = float('inf')
    else:
        max_raw = int(max_mb * 1024 * 1024)

    # Compute max pixels allowed so raw data fit under max_raw
    max_pixels = max_raw // channels
    orig_pixels = hdr0.width * hdr0.height
    if orig_pixels > max_pixels:
        scale = math.sqrt(max_pixels / orig_pixels)
        w = max(1, int(hdr0.width * scale) - PADDING)
        h = max(1, int(hdr0.height * scale) - PADDING)
        logger.info(f"Resizing cover from {hdr0.width}×{hdr0.height} to {w}×{h}")
    else:
        w, h = hdr0.width, hdr0.height

    # Calculate embedding capacities
    pixel_bytes = w * h * channels
    first_capacity = max(0, pixel_bytes - metadata_bits) * lsb
    std_capacity = pixel_bytes * lsb
    if first_capacity <= 0 or std_capacity <= 0:
        raise ValueError("Cover too small for embedding with given LSB and metadata size.")

    # Determine number of chunks needed
    extra_bits = max(0, total_bits - first_capacity)
    chunks = 1 + math.ceil(extra_bits / std_capacity)
    logger.info(f"Will split payload into {chunks} images (capacity per chunk ≈{std_capacity/8:.1f} B)")

    # Read and resize pixels
    signature, orig_chunks = read_png_data(png_path)
    _, raw_pixels = process_png_pixels(png_path)
    pixels = (resize_pixel_data(raw_pixels, hdr0.width, hdr0.height, channels, w, h)
              if (w, h) != (hdr0.width, hdr0.height) else raw_pixels)

    # Rebuild chunk lists with updated IHDR
    pre, post, seen = [], [], False
    hdr = namedtuple('PngHeader', hdr0._fields)(w, h,
                                                hdr0.bit_depth, hdr0.color_type,
                                                hdr0.compression, hdr0.filter_method,
                                                hdr0.interlace)
    for ctype, cdata, crc in orig_chunks:
        if ctype == b'IDAT':
            seen = True
            continue
        if not seen:
            if ctype == b'IHDR':
                ihdr = struct.pack('>IIBBBBB', w, h,
                                   hdr0.bit_depth, hdr0.color_type,
                                   hdr0.compression, hdr0.filter_method,
                                   hdr0.interlace)
                pre.append((b'IHDR', ihdr, None))
            else:
                pre.append((ctype, cdata, crc))
        else:
            post.append((ctype, cdata, crc))

    # Prepare metadata
    md5sum = calculate_file_md5(payload_path)
    metadata = struct.pack(METADATA_FORMAT, METADATA_MAGIC, lsb,
                           payload_size, chunks, md5sum)

    # Embed and write
    bit_pos = 0

    with open(payload_path, 'rb') as pf:
        for idx in range(chunks):
            out_png = f"{output_prefix}_part{idx+1}.png"
            buf = bytearray(pixels)
            # First chunk: metadata
            if idx == 0:
                buf[:metadata_bits] = embed_bits(buf[:metadata_bits], metadata, 1)
                avail = first_capacity
                start = metadata_bits
            else:
                avail = std_capacity
                start = 0
            to_write = min(avail, total_bits - bit_pos)
            if to_write:
                pixels_needed = math.ceil(to_write / lsb)
                bytes_needed = math.ceil(to_write / 8)
                chunk_data = pf.read(bytes_needed)
                buf[start:start+pixels_needed] = embed_bits(buf[start:start+pixels_needed], chunk_data, lsb)
                bit_pos += to_write

            comp = create_png_data(hdr, buf)
            new_chunks = pre + [(b'IDAT', comp, None)] + post
            write_png_data(out_png, signature, new_chunks)

            # Check size only if max limit was set
            if max_raw != float('inf'):
                size = os.path.getsize(out_png)
                if size > max_raw:
                    raise ValueError(f"Output {out_png} size {size} exceeds max size {max_raw} bytes")

            logger.info(f"Wrote {out_png}")
            pct = bit_pos / total_bits * 100
            sys.stdout.write(f"\r[+] Injecting: {pct:.1f}%")
            sys.stdout.flush()
        print()

    print(f"Injection complete: {chunks} files.")


import math
import time
def extract_payload(prefix):
    """Extract a hidden payload from one or more PNGs without distortion."""
    logger.info("Extraction start: %s", prefix)
    # Find chunk files
    files = []
    for i in range(1, 1000):
        fn = f"{prefix}_part{i}.png"
        if os.path.exists(fn):
            files.append(fn)
        else:
            break
    if not files:
        single = f"{prefix}.png"
        if os.path.exists(single):
            files = [single]
        else:
            raise IOError("No PNGs with that prefix found")
    
    # Process first file to get metadata
    hdr, pixel_data = process_png_pixels(files[0])
    w, h = hdr.width, hdr.height
    channels = 3 if hdr.color_type == 2 else 4
    pixel_bytes = w * h * channels
    
    # Extract metadata with 1 LSB (always)
    meta_bits = METADATA_SIZE * 8
    meta = extract_bits(pixel_data[:meta_bits], 1, METADATA_SIZE)
    magic, lsb, psize, chunks, md5sum = struct.unpack(METADATA_FORMAT, meta)
    if magic != METADATA_MAGIC:
        raise ValueError("Metadata magic mismatch - not a valid stego file")
    
    total_bits = psize * 8
    logger.info("Extracting: %d bytes, %d chunks, %d LSB", psize, chunks, lsb)
    
    if chunks != len(files):
        raise ValueError(f"Metadata says {chunks} parts, found {len(files)}")
    
    out_path = f"{prefix}_extracted.dat"
    bits_read = 0

    with open(out_path, 'wb') as outf:
        # First chunk after metadata
        avail = (pixel_bytes - meta_bits) * lsb
        to_read = min(avail, total_bits - bits_read)
        if to_read > 0:
            need_bytes = (to_read + 7) // 8
            data = extract_bits(pixel_data[meta_bits:], lsb, need_bytes)
            outf.write(data)
            bits_read += to_read
        
        # Process additional chunks
        for fn in files[1:]:
            if bits_read >= total_bits:
                break
                
            _, pixel_data = process_png_pixels(fn)
            avail = len(pixel_data) * lsb
            to_read = min(avail, total_bits - bits_read)
            if to_read <= 0:
                break
                
            need_bytes = (to_read + 7) // 8
            data = extract_bits(pixel_data, lsb, need_bytes)
            outf.write(data)
            bits_read += to_read
            
            # updated: use bit-level progress and drop elapsed
            pct = bits_read / total_bits * 100
            sys.stdout.write(
                f"\r[+] Extracting: {pct:.1f}%"
            )
            sys.stdout.flush()
        print()
    
    # Finalize output file
    final_size = os.path.getsize(out_path)
    if final_size > psize:
        with open(out_path, 'rb+') as f:
            f.truncate(psize)
    elif final_size < psize:
        with open(out_path, 'ab') as f:
            f.write(b'\x00' * (psize - final_size))
    
    # Verify checksum
    actual_md5 = calculate_file_md5(out_path).hex()
    expected_md5 = md5sum.hex()
    if actual_md5 != expected_md5:
        print(f"[!] Checksum mismatch: expected={expected_md5} actual={actual_md5}")
    else:
        print(f"[+] Checksum verified: {actual_md5}")
    
    print(f"[+] Extraction complete: {out_path}")
    return out_path

def display_banner():
    print(r"""
██████╗ ██╗   ██╗██████╗ ██╗██╗  ██╗
██╔══██╗██║   ██║██╔══██╗██║██║ ██╔╝
██║  ██║██║   ██║██║  ██║██║█████╔╝ 
██║  ██║██║   ██║██║  ██║██║██╔═██╗ 
██████╔╝╚██████╔╝██████╔╝██║██║  ██╗
╚═════╝  ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═╝
""")
    print("=" * 50)

def get_input(prompt, validator=None, default=None):
    while True:
        try:
            full = f"{prompt}"
            if default is not None:
                full += f" [default: {default}]"
            full += ": "
            resp = input(full).strip()
            if not resp and default is not None:
                return default
            if not resp:
                raise ValueError("Input cannot be empty")
            if validator:
                return validator(resp)
            return resp
        except Exception as e:
            print(f"  [!] Error: {e}")

def validate_file_exists(path):
    if not os.path.exists(path):
        raise ValueError("File not found")
    return path

def validate_lsb(s):
    n = int(s)
    if not 1 <= n <= 8:
        raise ValueError("LSB must be 1–8")
    return n

def validate_int(s):
    try:
        return int(s)
    except:
        raise ValueError("Must be an integer")

def validate_yes_no(s):
    s = s.lower()
    if s in ('y', 'yes'):
        return True
    if s in ('n', 'no'):
        return False
    raise ValueError("Enter y/n")

def inject_interactive():
    print("\n[+] Payload Injection Mode")
    png_path = get_input("1. PNG cover file", validator=validate_file_exists)
    payload = get_input("2. Payload file to hide", validator=validate_file_exists)
    lsb = get_input("3. Number of LSB bits (1–8)", validator=validate_lsb)
    prefix = get_input("4. Output filename prefix", default="output")

    def validate_mb_size(s):
        try:
            return float(s)
        except:
            raise ValueError("Must be a number (can be decimal or integer)")

    max_mb_input = get_input("5. Max output file size in MB (blank = no limit)", default="")
    max_mb = float(max_mb_input) if max_mb_input else None


    try:
        hdr = read_png_header(png_path)
        validate_png_for_stego(hdr)
    except Exception as e:
        print(f"[!] Invalid PNG: {str(e)}")
        return

    num_bytes = hdr.width * hdr.height * (3 if hdr.color_type == 2 else 4)
    meta_px = METADATA_SIZE * 8

    print(f"\nCover: {hdr.width}×{hdr.height}, bytes={num_bytes}")
    print(f"Payload: {os.path.getsize(payload) / (1024 * 1024):.2f}MB")

    if get_input("Proceed with injection? (y/n)", validator=validate_yes_no):
        inject_payload(png_path, payload, lsb, prefix, max_mb)
    else:
        print("[!] Injection cancelled")


def extract_interactive():
    print("\n[+] Payload Extraction Mode")
    prefix = get_input("Enter filename prefix", default="output")
    try:
        extract_payload(prefix)
    except Exception as e:
        print(f"[!] Extraction failed: {str(e)}")

def main_menu():
    display_banner()
    while True:
        print("\nMain Menu:")
        print("  1. Inject payload")
        print("  2. Extract payload")
        print("  3. Exit")
        choice = get_input("Select option", validator=validate_int)
        if choice == 1:
            inject_interactive()
        elif choice == 2:
            extract_interactive()
        elif choice == 3:
            print("Goodbye!")
            break
        else:
            print("[!] Invalid choice")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        logger.exception("Fatal error")

        print(f"\n[!] Error: {e}\nSee dudik.log for details")
