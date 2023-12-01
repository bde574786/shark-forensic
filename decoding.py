def decode_utf16(string):
    return string.decode('utf-16le').rstrip('\x00')