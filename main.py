import os
import cbor2
from plyvel import DB, IteratorInvalidError
from bitcoin import BitcoinRPC

BITCOIN_RPC_ADDRESS = os.getenv("BITCOIN_RPC_ADDRESS") or "http://127.0.0.1:8443"
BITCOIN_RPC_USER = os.getenv("BITCOIN_RPC_USER")
BITCOIN_RPC_PASSWORD = os.getenv("BITCOIN_RPC_PASSWORD")

bitcoin = BitcoinRPC(BITCOIN_RPC_ADDRESS, BITCOIN_RPC_USER, BITCOIN_RPC_PASSWORD)

next_block = bitcoin.getblockchaininfo()["blocks"]

db = DB("db", create_if_missing=True)


def main():
    try:
        with db.raw_iterator() as ri:
            ri.seek_to_last()
            blockheight = int.from_bytes(ri.key(), "big")
    except IteratorInvalidError:
        blockheight = 0

    while blockheight < (next_block + 10):
        inspect_block(blockheight)
        blockheight += 1


def inspect_block(blockheight):
    block = block = bitcoin.getblock(bitcoin.getblockhash(blockheight), 2)
    blockdata = {}
    references = {blockheight: blockdata}
    for tx in block["tx"]:
        for vout in tx["vout"]:
            # get data for transactions in this block
            template = templatize(vout["scriptPubKey"]["asm"])
            typn = get_or_set_txtype("script_pub_key: " + template)
            blockdata.setdefault(typn, 0)
            blockdata[typn] += 1
        for vin in tx["vin"]:
            # get witness or p2sh data regarding previous txs in other blocks
            if (witness := vin.get("txinwitness")) and len(witness) <= 2:
                script = bitcoin.decodescript(witness[-1])
                prefix = "p2sh"
            elif (
                "scriptSig" in vin
                and (asm := vin["scriptSig"]["asm"])
                and asm[0] == "0"
            ):
                script = bitcoin.decodescript(asm.split(" ")[-1])
                prefix = "p2wsh"
            else:
                continue
            template = templatize(script["asm"])
            typn = get_or_set_txtype(prefix + ": " + template)
            txid = vin["txid"]
            h = bitcoin.getblock(bitcoin.getrawtransaction(txid, True), 1)["height"]
            hdata = cbor2.loads(db.get(h.to_bytes(4, "big")))
            references[h] = hdata
            hdata.setdefault(typn, 0)
            hdata[typn] += 1
    with db.write_batch() as b:
        for blockn, value in references.items():
            print(blockn, value)
            b.put(blockn.to_bytes(4, "big"), cbor2.dumps(value))


def templatize(asm):
    template = []
    for word in asm.split(" "):
        if word.startswith("OP_"):
            template.append(word)
        else:
            template.append(str(len(word)))
    return " ".join(template)


try:
    with open("txtypes.cbor", "rb") as fp:
        txtypes = cbor2.load(fp)
except FileNotFoundError:
    txtypes = {}


def get_or_set_txtype(template):
    if typ := txtypes.get(template):
        return typ
    else:
        typn = len(txtypes)
        txtypes[template] = typn
        with open("txtypes.cbor", "wb") as fp:
            cbor2.dump(txtypes, fp)
        return typ


try:
    main()
finally:
    db.close()
