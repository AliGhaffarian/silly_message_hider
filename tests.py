from msg_hider import *
def test_encode(try_message : str):
    if loadkeys() is None:
        newkeys()
        loadkeys()
    image = open('./diagram.png', 'rb').read()
    encoded = encode_msg(
            MY_KEYS[0], 
            try_message.encode(),
            image
            )

    decoded = extract_msg(
            MY_KEYS[1],
            encoded,
            MY_KEYS[0]
            )

    assert try_message.encode() == decoded 


if __name__ == "__main__":
    test_encode('0' * 246)
    test_encode('hahha')
    test_encode('')
    test_encode('\x21\x24')
    test_encode('23423432' * 2048)
    print('passed')

