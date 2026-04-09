def little_endian_to_int(hex_str):
    return int.from_bytes(bytes.fromhex(hex_str), 'little')


def read_varint(data, i):
    prefix = int(data[i:i+2], 16)

    if prefix < 0xfd:
        return prefix, i + 2
    elif prefix == 0xfd:
        return little_endian_to_int(data[i+2:i+6]), i + 6
    elif prefix == 0xfe:
        return little_endian_to_int(data[i+2:i+10]), i + 10
    else:
        return little_endian_to_int(data[i+2:i+18]), i + 18


def decode_transaction(hex_string):
    tx = {}
    i = 0

    # Version
    tx['version'] = little_endian_to_int(hex_string[i:i+8])
    i += 8

    # Marker + Flag
    tx['marker'] = hex_string[i:i+2]
    tx['flag'] = hex_string[i+2:i+4]
    i += 4

    # Inputs
    input_count, i = read_varint(hex_string, i)
    tx['inputs'] = []

    for _ in range(input_count):
        raw_txid = hex_string[i:i+64]
        txid = ''.join(reversed([raw_txid[j:j+2] for j in range(0, 64, 2)]))
        i += 64

        vout = little_endian_to_int(hex_string[i:i+8])
        i += 8

        script_len, i = read_varint(hex_string, i)
        script_sig = hex_string[i:i+script_len*2]
        i += script_len * 2

        sequence = hex_string[i:i+8]
        i += 8

        tx['inputs'].append({
            "txid": txid,
            "vout": vout,
            "scriptSig": script_sig,
            "sequence": sequence
        })

    # Outputs
    output_count, i = read_varint(hex_string, i)
    tx['outputs'] = []

    for _ in range(output_count):
        amount = little_endian_to_int(hex_string[i:i+16])
        i += 16

        script_len, i = read_varint(hex_string, i)
        script_pubkey = hex_string[i:i+script_len*2]
        i += script_len * 2

        tx['outputs'].append({
            "amount": amount,
            "scriptPubKey": script_pubkey
        })

    # Witness
    tx['witness'] = []

    for _ in range(input_count):
        items, i = read_varint(hex_string, i)
        stack = []

        for _ in range(items):
            size, i = read_varint(hex_string, i)
            item = hex_string[i:i+size*2]
            i += size * 2
            stack.append(item)

        tx['witness'].append(stack)

    # Locktime
    tx['locktime'] = little_endian_to_int(hex_string[i:i+8])

    return tx


# TEST
tx_hex = "0200000000010131811cd355c357e0e01437d9bcf690df824e9ff785012b6115dfae3d8e8b36c10100000000fdffffff0220a107000000000016001485d78eb795bd9c8a21afefc8b6fdaedf718368094c08100000000000160014840ab165c9c2555d4a31b9208ad806f89d2535e20247304402207bce86d430b58bb6b79e8c1bbecdf67a530eff3bc61581a1399e0b28a741c0ee0220303d5ce926c60bf15577f2e407f28a2ef8fe8453abd4048b716e97dbb1e3a85c01210260828bc77486a55e3bc6032ccbeda915d9494eda17b4a54dbe3b24506d40e4ff43030e00"

decoded = decode_transaction(tx_hex)

print(decoded)

# Save to output.txt
with open("output.txt", "w") as f:
    f.write(str(decoded))