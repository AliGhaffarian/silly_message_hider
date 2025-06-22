import os
try:
    import rsa
except:
    os.system('pip install rsa')
from msg_hider import *


DEFAULT_OUT_FNAME = 'out.png' 

def clear_screen():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def handle_load_keys():
    keys = loadkeys()
    if keys is None:
        print('no keys found')
        handle_new_keys()
    print(f'your public key is')
    print(MY_KEYS[0].save_pkcs1('PEM').decode())


def handle_new_keys():
    print("generating new keys")
    newkeys()
    print(f"new keys are written at directory {os.getcwd()} and files {PRIVATE_KEY_FILENAME},{PUBLIC_KEY_FILENAME}")

def handle_encode_n_write_msg():
    carrier_path= input("path of image: ")
    message = input("message: ")
    out_file = input(f"output filename(default is {DEFAULT_OUT_FNAME}): ")
    if len(out_file) == 0:
        out_file = DEFAULT_OUT_FNAME

    public_key_path= input("receiver's publickey file : ")
    print(f"making {out_file}")
    public_key = open(public_key_path, 'rb').read()
    public_key = rsa.PublicKey.load_pkcs1(public_key)

    carrier_bytes = open(carrier_path, "rb").read()
    encrypted = encode_msg(public_key, message.encode(), carrier_bytes)
    open(out_file, "wb").write(encrypted)
    print("done")

def handle_extract_msg():
    input_path = input(f"path of image(default {DEFAULT_OUT_FNAME}): ")
    if len(input_path) == 0:
        input_path = DEFAULT_OUT_FNAME

    sender_pub_key_path = input(f"sender's publickey file : ")

    print("extracting")

    sender_pub_key = open(sender_pub_key_path, 'rb').read()
    sender_pub_key = rsa.PublicKey.load_pkcs1(sender_pub_key)

    content = open(input_path, 'rb').read()
    msg = extract_msg(MY_KEYS[1], content, sender_pub_key)

    print(f"hidden message is {msg}")

def handle_exit():
    from sys import exit
    exit(0)

menu_handler = [handle_new_keys, handle_encode_n_write_msg, handle_extract_msg, handle_exit]

menu = """\
[1]: generate new keys
[2]: encode_message
[3]: extract message
[4]: exit
"""
if __name__ == "__main__":
    while True:
        try:
            handle_load_keys()
            menu_input = input(menu)
            menu_handler[int(menu_input) - 1]()
        except Exception as e:
            print(e)
        
        input('press enter to continue...')
        clear_screen()
            
