import os
import sys

def rc4_init(key):
    """Initialize the RC4 state with the given key."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def rc4_encrypt(data, key):
    """Encrypt data using RC4 algorithm."""
    if isinstance(key, str):
        key = key.encode()
    
    S = rc4_init(key)
    i = j = 0
    result = bytearray()
    
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    
    return bytes(result)

def encrypt_file(input_path, output_path, key):
    """Encrypt a file using RC4."""
    try:
        if not os.path.exists(input_path):
            print(f"Error: Input file '{input_path}' not found.")
            return False
        
        with open(input_path, 'rb') as f:
            data = f.read()
        
        encrypted_data = rc4_encrypt(data, key)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        print(f"File encrypted successfully. Saved to {output_path}")
        return True
    
    except Exception as e:
        print(f"Error during encryption: {str(e)}")
        return False

def main():
    if len(sys.argv) != 4:
        print("Usage: python rc4_encrypt.py <input_file> <output_file> <key>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    key = sys.argv[3]
    
    if not key:
        print("Error: Key cannot be empty.")
        sys.exit(1)
    
    encrypt_file(input_file, output_file, key)

if __name__ == "__main__":
    main()