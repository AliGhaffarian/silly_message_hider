import rsa
import rsa.common
#constants
RSA_KEY_LENGTH=2048
PRIVATE_KEY_MARKER="RSA PRIVATE KEY"
PUBLIC_KEY_MARKER="RSA PUBLIC KEY"
PNG_TRAILER=b"\x49\x45\x4e\x44\xae\x42\x60\x82"

#global vars
SIGN_HASH_METHOD = "SHA-512"
SIGN_HASH_METHOD_SIZE = 256 # i have no idea why
PRIVATE_KEY_FILENAME = "private_key.pem"
PUBLIC_KEY_FILENAME = "public_key.pem"

MY_KEYS = []

def encrypt_message(pub_key : rsa.PublicKey, msg : bytes):
    max_len_to_encrypt = rsa.common.byte_size(pub_key.n) - 11
    result = b""

    encrypted_offset = 0
    sign = rsa.sign(msg, MY_KEYS[1], SIGN_HASH_METHOD)

    for i in range((len(msg) // max_len_to_encrypt)):
        current_offset = i * max_len_to_encrypt

        this_chunk_content = msg[ current_offset : current_offset + max_len_to_encrypt]

        encrypted = rsa.encrypt(this_chunk_content, pub_key)
        result += encrypted

        encrypted_offset = current_offset + max_len_to_encrypt

    #in case of the  message length not being a multiple of max_len_to_encrypt (leftover bytes)
    if encrypted_offset < len(msg):
        this_chunk_content = msg[encrypted_offset: len(msg) ]
        encrypted = rsa.encrypt(this_chunk_content, pub_key)

        result += encrypted

    result = sign + result
    return result


def encode_msg(pub_key : rsa.PublicKey, msg : bytes, carrier : bytes):

    trailer_offset = carrier.find(PNG_TRAILER)
    trailer_offset += len(PNG_TRAILER)

    carrier = carrier[:trailer_offset] #strip off any trailing data

    #append encrypted data
    carrier += encrypt_message(pub_key, msg)

    return carrier

def decrypt_message_and_verify(private_key : rsa.PrivateKey, content, sender_pubkey : rsa.PublicKey):
    data_chunk_len = rsa.common.byte_size(sender_pubkey.n)

    result = b''
    sign = content[ :SIGN_HASH_METHOD_SIZE ]

    content = content[SIGN_HASH_METHOD_SIZE:]
    current_offset = 0
    while True:
        if current_offset + data_chunk_len >= len(content):
            break

        this_chunk_content = content[ current_offset : current_offset + data_chunk_len ]
        current_offset += data_chunk_len

        decrypted = rsa.decrypt(this_chunk_content, private_key)
        result += decrypted


    if current_offset < len(content):
        this_chunk_content = content[ current_offset : len(content) ]
        decrypted = rsa.decrypt(this_chunk_content, private_key)
        result += decrypted

    rsa.verify(result, sign, sender_pubkey)

    return result

def extract_msg(private_key : rsa.PrivateKey, content, sender_pubkey : rsa.PublicKey):
    content_offset = content.find(PNG_TRAILER)
    content_offset += len(PNG_TRAILER) 

    return decrypt_message_and_verify(private_key, content[content_offset:], sender_pubkey)

def load_carrier_file(fname):
    global image_bytes
    image_bytes = open(fname, "rb").read()


def newkeys():
    global MY_KEYS
    MY_KEYS.clear()
    keys = rsa.newkeys(
            nbits=RSA_KEY_LENGTH
            )
    MY_KEYS.append(keys[0])
    MY_KEYS.append(keys[1])

    open(PRIVATE_KEY_FILENAME, "wb").write(MY_KEYS[1].save_pkcs1("PEM"))
    open(PUBLIC_KEY_FILENAME, "wb").write(MY_KEYS[0].save_pkcs1("PEM"))

def loadkeys():
    global MY_KEYS
    MY_KEYS.clear()

    try:
        buff = open(PUBLIC_KEY_FILENAME, "rb").read()
    except FileNotFoundError:
        return None

    MY_KEYS.append(rsa.PublicKey.load_pkcs1(buff, "PEM"))

    try:
        buff = open(PRIVATE_KEY_FILENAME, "rb").read()
    except FileNotFoundError:
        return None

    MY_KEYS.append(rsa.PrivateKey.load_pkcs1(buff, "PEM"))
    return MY_KEYS
