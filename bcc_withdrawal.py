import bitcoin
import requests
import sys
from blockchain import *
import argparse



def fmt(g,n):
    return format(g/10 ** n,'0.%sf' % n).rstrip('0').rstrip('.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Bitcoin cash utils v 1.0")
    parser.add_argument("-p","--private_key", help="private key", type=str, metavar=('ID'))
    parser.add_argument("-o","--pay_out", help="payout address", type=str, metavar=('ID'))

    args = parser.parse_args()
    if not args.private_key:
        print("\nError:  no private key provided")
        sys.exit(0)

    if not args.pay_out:
        print("\nError:  no payout address provided")
        sys.exit(0)


    priv = args.private_key
    try:
        pub = bitcoin.privtopub(priv)
    except Exception:
        print("\nError:  private key invalid")
        sys.exit(0)

    address = bitcoin.pubtoaddr(pub)
    raw_pub = unhexlify(pub)
    pay_out = args.pay_out
    fee_rate = 5
    if not is_address_valid(pay_out):
        print("\nError:  Payout address invalid!!! %s\n" % pay_out)
        sys.exit(0)


    r = requests.get("https://api.blocktrail.com/v1/bcc/address/%s?api_key=MY_APIKEY"
                     % address)
    a = r.json()
    print("\nBitcoin cash address: %s\n" % address)
    print("Confirmed balance: %s BCC" % (int(a['balance'])/100000000))
    print("Unconfirmed balance: %s\n" % ((a['unconfirmed_received'] - a['unconfirmed_sent'])/100000000))

    r = requests.get("https://api.blocktrail.com/v1/bcc/address/%s/unspent-outputs?api_key=MY_APIKEY&limit=200"
                     % address)

    inputs = r.json()
    pks = 0
    tx_amount = 0
    tx_ins = []
    print("Dig unspent coins:")
    for coin in inputs["data"]:
        i = Input((unhexlify(coin["hash"])[::-1], coin["index"]),
                  unhexlify(coin["script_hex"]),
                  0xffffffff)
        i.amount = coin["value"]
        i.pk_script = unhexlify(coin["script_hex"])
        tx_ins.append(i)
        pks += len(coin["script_hex"])/2
        tx_amount += coin["value"]
        print(coin["hash"],coin["index"], fmt(coin["value"],8) )
    raw_address = decode_base58(pay_out)[1:-4]
    print("_" * 80)
    print("Collected %s inputs for %s BCC \n" % (len(tx_ins), tx_amount/100000000))


    ptpkh = OPCODE["OP_DUP"] + OPCODE["OP_HASH160"] + b'\x14%s' + OPCODE["OP_EQUALVERIFY"] + OPCODE["OP_CHECKSIG"]
    p2sh = OPCODE["OP_HASH160"] + b'\x14%s' + OPCODE["OP_EQUAL"]

    if address[0] == '1':
        tx_out = [Output(tx_amount, ptpkh % raw_address), ]
    else:
        tx_out = [Output(tx_amount, p2sh % raw_address), ]

    tx = Transaction(1, tx_ins, tx_out, 0)

    fee = int((len(tx.serialize()) + len(tx.tx_in) * (72 + 33) - pks) * (fee_rate))
    if fee < 1000:
        fee = 1000
    tx.tx_out[-1].value = tx_amount -  fee

    hashtype = SIGHASH_ALL | SIGHASH_FORKID
    # prepare hash for signature
    all_inputs = b''
    all_sequnce = b''
    for i in tx.tx_in:
        all_inputs += i.outpoint[0]+int(i.outpoint[1]).to_bytes(4, 'little')
        all_sequnce += int(i.sequence).to_bytes(4, 'little')
    all_outs = b''
    for i in tx.tx_out:
        all_outs += i.value.to_bytes(8, 'little') + to_var_int(len(i.pk_script.raw)) + i.pk_script.raw

    hashPrevouts = double_sha256(all_inputs)
    hashSequence = double_sha256(all_sequnce)
    hashOuts = double_sha256(all_outs)

    for index, input in enumerate(tx.tx_in):
        subscript = input.pk_script
        sighash = int(tx.version).to_bytes(4, 'little')
        sighash += hashPrevouts
        sighash += hashSequence
        sighash += input.outpoint[0]+int(input.outpoint[1]).to_bytes(4, 'little')
        sighash += to_var_int(len(subscript)) + subscript
        sighash += int(input.amount).to_bytes(8, 'little')
        sighash += int(input.sequence).to_bytes(4, 'little')
        sighash += hashOuts
        sighash += tx.lock_time.to_bytes(4, 'little')
        sighash += int(hashtype).to_bytes(4, 'little')
        sighash = double_sha256(sighash)
        rawsig = bitcoin.ecdsa_raw_sign(hexlify(sighash), priv)
        s = bitcoin.der_encode_sig(*rawsig)
        input.signature = unhexlify(s)  + int(hashtype).to_bytes(1, 'little')
    for input in tx.tx_in:
        input.sig_script = Script(
            len(input.signature).to_bytes(1, 'little') +
            input.signature +
            len(raw_pub).to_bytes(1, 'little') +
            raw_pub)
    raw_tx = tx.serialize()
    print("Payout transaction: %s" % rh2s(double_sha256(raw_tx)) )
    print("amount %s BCC miner fee %s BCC [%s satoshi/byte]:\n" % (fmt(tx_amount -  fee, 8),
                                                                             fmt(fee, 8),
                                                                             int(fee/len(raw_tx))))
    print(hexlify(raw_tx).decode())

