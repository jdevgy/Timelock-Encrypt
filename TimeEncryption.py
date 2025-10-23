#!/usr/bin/env python3
"""
double_time_lock.py

Two-layer encryption:
1. First: RSA time-lock puzzle encryption (sequential squaring).
2. Second: PBKDF2 brute-force layer.

Decryption reverses:
    PBKDF2 brute-force -> Time-lock puzzle.
"""

import os, sys, argparse, struct, random, time, math, hashlib, hmac
from tqdm import tqdm
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util import number
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import binascii
import io

#---------------------------------------------------
VERSION = 4

versionrequ  = f"v{VERSION}enc".encode('utf-8')
MAGIC_TLP = f'TIME_TLP_LAYER_{VERSION}enc'.encode('utf-8') 
VERSION_TLP = VERSION


# ------------------ Common Constants ------------------
AES_KEY_LEN = 32
IV_LEN = 16
SALT_LEN = 16

MAGIC_PASSWORD_CHECK = b'ENCRYPTED_WITH_PASSWORD_MAGIC' # if password provided for magic, always below 255 characters (1 byte)

# ------------------ Time-lock Puzzle ------------------
CAPSULE_LEN = AES_KEY_LEN
DEFAULT_MOD_BITS = 1024
DEFAULT_CALIB_SAMPLES = 20

def hexdump(byte_data):
    """Convert bytes to a plain hexadecimal string."""
    return binascii.hexlify(byte_data).decode('utf-8')

def reverse_hexdump(hex_string):
    """Convert a hexadecimal string back to bytes."""
    return binascii.unhexlify(hex_string)


def check_file_format(content):
    try:
        hex_string = content.decode('utf-8')
        binascii.unhexlify(hex_string)  # Check if it can be converted from hex
        print("input is hex")
        return 2
    except (binascii.Error, ValueError, UnicodeDecodeError):
        print("input is bytes")
        return 1
        
def get_hex_sha256_checksum(input_string):
    byte_string = input_string.encode()
    sha256_hash = hashlib.sha256()
    sha256_hash.update(byte_string)
    return sha256_hash.hexdigest()

def get_sha256_bytes(bytesni):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(bytesni)
    return sha256_hash.digest()

def get_hex_md5(input_string):
    byte_string = input_string.encode()
    md5_hash = hashlib.md5()
    md5_hash.update(byte_string)
    return md5_hash.hexdigest()


def get_md5(inputbytes):
    md5_hash = hashlib.md5()
    md5_hash.update(inputbytes)
    return md5_hash.digest()

def get_hex_sha1_checksum(input_string):
    byte_string = input_string.encode()
    sha1_hash = hashlib.sha1()
    sha1_hash.update(byte_string)
    return sha1_hash.hexdigest()
        
def sha256(b): return hashlib.sha256(b).digest()
def int_to_bytes(n): return n.to_bytes((n.bit_length() + 7) // 8 or 1, 'big')
def bytes_to_int(b): return int.from_bytes(b, 'big')

def generate_modulus(bits):
    half = bits // 2
    p = number.getPrime(half)
    q = number.getPrime(half)
    while p == q: q = number.getPrime(half)
    return p, q, p*q

def fast_compute_a_2powT_modN(a, T, p, q, N):
    phi = (p - 1)*(q - 1)
    e = pow(2, T, phi)
    return pow(a, e, N)

def sequential_squarings(a, T, N, progress_callback=None):
    v = a % N
    for i in range(T):
        v = (v * v) % N
        if progress_callback: progress_callback(i+1, T)
    return v


def looks_like_tlp(candidate: bytes) -> bool:
    """
    Fast, cheap checks to decide whether `candidate` is likely a valid TLP blob:
     - starts with MAGIC_TLP
     - version equals VERSION_TLP
     - nlen and alen parse and are plausible (not gigantic / not tiny)
     - header lengths are consistent with total candidate length
    Returns True if candidate *looks like* a valid TLP header; False otherwise.
    """


    try:
        if not candidate.startswith(MAGIC_TLP):
       #     print("Error 1")
            return False


        base = len(MAGIC_TLP)
        # need at least 4 bytes for version and 4 for nlen, etc.
        min_hdr_len = base + 4 + 4 + 1 + 4 + 1 + 8 + CAPSULE_LEN + IV_LEN
        # minimal safe bound: magic + version + nlen+ at least 1 byte of N + alen + 1 byte of a + T(8) + capsule + iv
        if len(candidate) < min_hdr_len:
            print("Error 2")
            return False

        # version
        ver = struct.unpack(">I", candidate[base:base+4])[0]
        if ver != VERSION_TLP:
            print("Error 3")
            return False

        off = base + 4
        # nlen
        nlen = struct.unpack(">I", candidate[off:off+4])[0]; off += 4
        if nlen < 16 or nlen > 65536:
            print("Error 4")
            return False

        return True
    except Exception:
        print("error: 9")
        return False
        

def calibrate_squaring_time(N, sample_count=DEFAULT_CALIB_SAMPLES):
    a = number.getRandomNBitInteger(min(64,N.bit_length())) % N
    for _ in range(5): a = pow(a,2,N)
    start=time.time()
    for _ in range(sample_count): a=pow(a,2,N)
    dur=time.time()-start
    return dur/sample_count if sample_count>0 else 0.01

def encrypt_tlp_layer(plaintext, password, desired_time_sec, mod_bits=DEFAULT_MOD_BITS):
    p,q,N = generate_modulus(mod_bits)
    per_sq = calibrate_squaring_time(N)
    T = max(1,int(math.ceil(desired_time_sec/per_sq)))
    a = number.getRandomRange(2,N-1)
    v = fast_compute_a_2powT_modN(a,T,p,q,N)
    K = get_random_bytes(AES_KEY_LEN)
    mask = sha256(int_to_bytes(v)+password)
    capsule = bytes(x^y for x,y in zip(K,mask[:AES_KEY_LEN]))
    iv = get_random_bytes(IV_LEN)
    cipher = AES.new(K,AES.MODE_CBC,iv)
    ciphertext = cipher.encrypt(pad(plaintext,AES.block_size))
    header = (
        MAGIC_TLP +
        struct.pack(">I",VERSION_TLP) +
        struct.pack(">I",mod_bits) +
        struct.pack(">I",len(int_to_bytes(N))) + int_to_bytes(N) +
        struct.pack(">I",len(int_to_bytes(a))) + int_to_bytes(a) +
        struct.pack(">Q",T) +
        capsule +
        iv
    )
    return header+ciphertext

def decrypt_tlp_layer(enc_bytes, password, show_progress=True):
    # parse header
    fview = memoryview(enc_bytes)
    pos = 0
    magic = fview[pos:pos+len(MAGIC_TLP)].tobytes(); pos+=len(MAGIC_TLP)
    if magic!=MAGIC_TLP: raise ValueError("Bad TLP magic")
    version=struct.unpack(">I",fview[pos:pos+4])[0]; pos+=4
    if version!=VERSION_TLP: raise ValueError("Bad TLP version")
    mod_bits=struct.unpack(">I",fview[pos:pos+4])[0]; pos+=4
    nlen=struct.unpack(">I",fview[pos:pos+4])[0]; pos+=4
    N=bytes_to_int(fview[pos:pos+nlen].tobytes()); pos+=nlen
    alen=struct.unpack(">I",fview[pos:pos+4])[0]; pos+=4
    a=bytes_to_int(fview[pos:pos+alen].tobytes()); pos+=alen
    T=struct.unpack(">Q",fview[pos:pos+8])[0]; pos+=8
    capsule=bytes(fview[pos:pos+CAPSULE_LEN]); pos+=CAPSULE_LEN
    iv=bytes(fview[pos:pos+IV_LEN]); pos+=IV_LEN
    ciphertext=bytes(fview[pos:])

    last=-1
    def cb(done,total):
        nonlocal last
        if show_progress:
            pct=int(done*100/total)
            if pct!=last:
                last=pct; print(f"[TLP] {pct}% {done}/{total}",end="\r")
    print(f"[TLP] Starting {T} squarings...")
    v = sequential_squarings(a,T,N,progress_callback=cb)
    print()
    mask=sha256(int_to_bytes(v)+password)
    K=bytes(x^y for x,y in zip(capsule,mask[:AES_KEY_LEN]))
    cipher=AES.new(K,AES.MODE_CBC,iv)
    return unpad(cipher.decrypt(ciphertext),AES.block_size)

# ------------------ PBKDF2 Brute Force Layer ------------------
PBKDF2_DKLEN=32
DEF_ITER_SEC=6000000  # benchmark iterations per second (provide --iterations ITERATIONS to change)

def getpassword(password_in, index, seed):
    #part one of pw
    password_in = password_in.hex()
    indexhash = get_hex_sha256_checksum(str(index)).encode()
    hmac_object = hmac.new(seed, indexhash, hashlib.sha256)
    hexhmac = hmac_object.hexdigest()
    pass_pone = get_hex_md5(hexhmac) 
    passwordpart = get_hex_sha1_checksum(password_in)
    password = pass_pone + passwordpart
    passwordfinal = get_hex_sha256_checksum(password)
    passbyt = passwordfinal.encode()
    return passbyt


def timed_pbkdf2(password, salt, iterations=None):
    if iterations is None:
        iterations = DEF_ITER_SEC
        #if no --iterations use 6M standard
    
    key = PBKDF2(password, salt, dkLen=PBKDF2_DKLEN, count=iterations, hmac_hash_module=SHA256)
    return key, iterations

    

def aes256cbcdec(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(ciphertext, AES.block_size)
    ciphertext=cipher.decrypt(padded)
    return ciphertext
    
    

def aes256cbcenc(key, iv, bytesin):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(bytesin, AES.block_size)
    ciphertext=cipher.encrypt(padded)
    return ciphertext
    
def getkeyoptional(password, time_salt, iterations):
    password_hashed = get_sha256_bytes(password.encode())
    keytlp,_ = timed_pbkdf2(password_hashed, time_salt, iterations=iterations)
    return keytlp
    
def optional_password_encrypt(password, time_iv, time_salt, iterations, bytedata):
    password_hashed = get_sha256_bytes(password.encode())
    iv_pass = get_md5(time_iv)
    keytlp,_ = timed_pbkdf2(password_hashed, time_salt, iterations=iterations)
    encbytes = aes256cbcenc(keytlp, iv_pass, bytedata)
    return encbytes
    
def optional_password_decrypt(encbytes, password, time_iv, time_salt, iterations):
    password_hashed = get_sha256_bytes(password.encode())
    iv_pass = get_md5(time_iv)
    keytlp, _ = timed_pbkdf2(password_hashed, time_salt, iterations=iterations)
    decrypted_data = aes256cbcdec(keytlp, iv_pass, encbytes)
    return decrypted_data

def ciphertext_join_bytes(ciphertext, magic):

    ciphertextfull = magic + ciphertext

def encrypt_final_layer(filename, password_input, desired_max_index, tlp_bytes, iterations, key_part):

    salt = os.urandom(SALT_LEN)
    seed = os.urandom(32)
    iv = os.urandom(16)
    max_index = int(desired_max_index)  #not meant to be accurate, but rather a delayed mechanism, TLP layer is more accurate for time.
    idx = random.randint(0, max_index - 1)
    key_part_encoded = key_part
    key_part_combined = getpassword(key_part_encoded, idx, seed)


    key, iters = timed_pbkdf2(key_part_combined, salt, iterations=iterations)
    ciphertext = aes256cbcenc(key, iv, tlp_bytes)

    if password_input == None:
        ciphertext = ciphertext
        PASSWORD_REQ = 0
    else:
        print("Time locking with a password, please save the password provided as you will need it to unlock")
        ciphertext_joined = MAGIC_PASSWORD_CHECK + ciphertext #for checking when decrypting 
        ciphertext_enc = optional_password_encrypt(password_input, iv, salt, iterations, ciphertext_joined)
        PASSWORD_REQ = 1
        ciphertext = ciphertext_enc

    if PASSWORD_REQ == 1:
        MAGIC_PASS_LEN = (len(MAGIC_PASSWORD_CHECK)).to_bytes()
    else:
        MAGIC_PASS_LEN = PASSWORD_REQ.to_bytes()


    outname=filename+".tloc.enc"
    with open(outname,'wb') as f:
        f.write(versionrequ)
        f.write(struct.pack(">I",VERSION))
        f.write(struct.pack(">I",iters))
        f.write(struct.pack(">Q",max_index))
        f.write(salt)
        f.write(seed)
        f.write(key_part_encoded)
        f.write(iv)
        f.write(MAGIC_PASS_LEN)
        f.write(ciphertext)
        

    with open(outname, 'rb') as fw:
        content=fw.read()
        datahex = hexdump(content)
        
    outhex=filename+".tloc.hex.enc"
    with open(outhex, 'w') as f:
        f.write(datahex)

    metadata = f"iterations {iters}\nmax_index {max_index}\nsalt {salt.hex()}\nseed {seed.hex()}\niv {iv.hex()}\nciphertext {ciphertext.hex()}"
   # print(metadata)
    print(f"[Final Saved HEX version {outhex}")
    print(f"[Final] Saved {outname}")
    return outname, outhex

def decrypt_final_layer(file, password, start_index=0):
    
    with open(file, 'rb') as f:
        content=f.read()
        filetype = check_file_format(content)


  
        if filetype == 2:
            datahex = reverse_hexdump(content)
            f = io.BytesIO(datahex)
            
        f.seek(0)
        magic = f.read(5)



        if magic != versionrequ:
            raise ValueError(f"Encryption is different version: \n this file you provided is version {magic} \n This file can decrypt {versionrequ}, please use correct version")
        version = struct.unpack(">I", f.read(4))[0]
        iters = struct.unpack(">I", f.read(4))[0]
        max_index = struct.unpack(">Q", f.read(8))[0]
        salt = f.read(SALT_LEN)
        seed = f.read(32)
        key_part_encoded = f.read(32)
        iv = f.read(16)
        LEN_PASS_MAGIC = f.read(1)
        ciphertext = f.read()

        
    LEN_PASS_MAGIC = int.from_bytes(LEN_PASS_MAGIC, byteorder='little')
  

    #LEN_PASS_MAGIC is 0 if no password
     
    if LEN_PASS_MAGIC == 0:
        print("File is not encrypted with password, timelocked only.")
    elif LEN_PASS_MAGIC == 0 and password is not None:
        print("--password was specified but this timelock file is not encrypted with a password, continuing without password input.") 

    elif LEN_PASS_MAGIC > 0 and password is not None:
        print("encrypted with password")
        key=getkeyoptional(password, salt, iters)
        iv_pass = get_md5(iv)
        cipher = AES.new(key, AES.MODE_CBC, iv_pass)
        try:
            candidate = unpad(cipher.decrypt(ciphertext), AES.block_size)
         
        except Exception:

            print("incorrect password")
            exit()
        ciphertext_joined = candidate
        extracted_magic = ciphertext_joined[:LEN_PASS_MAGIC]

        if MAGIC_PASSWORD_CHECK == extracted_magic:
            print("correct password and magic. Continuing")
            ciphertext = ciphertext_joined[LEN_PASS_MAGIC:]
            
        else:
            print(f"Key unlocked outer layer however magic was incorrect\nextracted magic: {extracted_magic} \nrequired magic: {MAGIC_PASSWORD_CHECK}")
            exit()
        
  
    elif LEN_PASS_MAGIC > 0 and password is None:
        print("This timelock requires a password, please specify it with --password")
        exit()



    print(f"[Final] Max index {max_index}, iters {iters}")

    with tqdm(total=max(0, max_index - start_index), desc="Brute-force PBKDF2", unit="try") as pbar:
        for j in range(start_index, max_index):
            idx = j
            pw_in = getpassword(key_part_encoded, idx, seed)

    
            key = PBKDF2(pw_in, salt, dkLen=PBKDF2_DKLEN, count=iters, hmac_hash_module=SHA256)
            cipher = AES.new(key, AES.MODE_CBC, iv)

            try:
                candidate = unpad(cipher.decrypt(ciphertext), AES.block_size)
            except Exception:
                # Wrong key -> unpad/decrypt failed
                pbar.update(1)
                continue

            # Fast header validation:
            if not looks_like_tlp(candidate):
               # print(f"\n[Final] Padding OK but not a plausible TLP at attempt {j} (len {len(candidate)})")
                pbar.update(1)
                continue

            print(f"\n[Final] Success at {j} (passed padding + header checks)")
            return candidate, key_part_encoded

    raise ValueError("Brute-force failed")


# ------------------ Combined High-Level ------------------
def double_encrypt(filename,password,tlp_time,max_index,iterations):
    key_part = os.urandom(32)
    with open(filename,'rb') as f: plain=f.read()
    print("[Step1] TLP layer...")
    tlp_bytes=encrypt_tlp_layer(plain,key_part,tlp_time)
    print("[Step2] PBKDF2 brute-force layer...")
    return encrypt_final_layer(filename,password,max_index,tlp_bytes, iterations, key_part)

def double_decrypt(filename, password, start_index=0):

    print("[Step1] Break PBKDF2 layer...")
    tlp_bytes, key_part = decrypt_final_layer(filename, password, start_index)

    print("[Step2] Solve TLP layer...")
    plain = decrypt_tlp_layer(tlp_bytes, key_part)

    outname = filename + ".dec"
    with open(outname, 'wb') as f:
        f.write(plain)
    print(f"[Done] Decrypted -> {outname}")


# ------------------ CLI ------------------
def main():
    parser=argparse.ArgumentParser(description="Double time-lock encryptor")
    sub=parser.add_subparsers(dest="cmd",required=True)
    pe=sub.add_parser("encrypt")
    pe.add_argument("file")
    pe.add_argument("--tlp-time",type=int,required=True,help="Seconds for TLP puzzle, ")
    pe.add_argument("--max-index",type=int,required=True,help="Desired max index for PBKDF brute force, not time accurate, but a baseline delay")
    pe.add_argument("--iterations",type=int,help="iterations solvable per second the target is for the pbkdf layer (default is for 6,000,000) increase depending on your hardware or CPU")
    pe.add_argument("--password",default=None,help="provide a password for extra security that will encrypt the plain text with AES-256-CBC before the time locking encryption, you will not be able to unlock the timelock without the password")
    pd=sub.add_parser("decrypt")
    pd.add_argument("file")
    pd.add_argument("--password",default=None)
    pd.add_argument("--start-index", type=int, default=0,help="Start the pbkdf brute force at a chosen index")

    args=parser.parse_args()
    

   
  
    
    if args.cmd == "encrypt":
        double_encrypt(args.file, args.password, args.tlp_time, args.max_index, args.iterations)
    else:
        # pass the verify flag into double_decrypt
        double_decrypt(args.file, args.password, args.start_index)


if __name__=="__main__":
    main()
