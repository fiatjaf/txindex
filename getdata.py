import cbor2
from plyvel import IteratorInvalidError
from binascii import unhexlify, Error as bError
from bitcoin.core.script import (
    CScript,
    CScriptOp,
    CScriptTruncatedPushDataError,
    CScriptInvalidError,
)
from pprint import pprint as pp

from globals import db, bitcoin, next_block


def main():
    load_txtypes()

    try:
        with db.raw_iterator() as ri:
            ri.seek_to_last()
            blockheight = int.from_bytes(ri.key(), "big")
    except IteratorInvalidError:
        blockheight = -1

    while blockheight < (next_block + 10):
        blockheight += 1
        inspect_block(blockheight)


def inspect_block(blockheight):
    block = bitcoin.getblock(bitcoin.getblockhash(blockheight), 2)
    blockdata = {}
    references = {blockheight: blockdata}

    # gather changes
    for tx in block["tx"]:
        for vout in tx["vout"]:
            # get data for transactions in this block
            template = script_to_template(vout["scriptPubKey"]["hex"])
            typn = get_or_set_txtype(tx["txid"], "script_pub_key: " + template)
            blockdata.setdefault(typn, 0)
            blockdata[typn] += 1
            if template == None or typn == None:
                pp(tx, "vout", vout, template, typn)
                exit()

        for vin in tx["vin"]:
            # get witness or p2sh data regarding previous txs in other blocks
            if (witness := vin.get("txinwitness")) and len(witness) > 2:
                template = "p2wsh: " + script_to_template(witness[-1])
            elif "coinbase" in vin:
                continue
            else:
                # this may be p2sh
                asm = vin["scriptSig"]["asm"]
                encoded_script = asm.split(" ")[-1]
                try:
                    template = script_to_template(encoded_script)
                except bError:
                    # this is not a script and so this is not p2sh
                    continue
                if template[0] == "[":
                    # raised an error, so this is probably not p2sh
                    # we were trying to parse a signature or something
                    # as if it was an encoded script
                    continue

                template = "p2sh: " + template

            typn = get_or_set_txtype(tx["txid"], template)
            txid = vin["txid"]
            blockhash = bitcoin.getrawtransaction(txid, True)["blockhash"]
            h = bitcoin.getblock(blockhash, 1)["height"]
            hdata = references.get(h) or cbor2.loads(db.get(h.to_bytes(4, "big")))
            references[h] = hdata
            hdata.setdefault(typn, 0)
            hdata[typn] += 1

            if template == None or typn == None:
                pp(tx, "vin", vin, template, typn)
                exit()

    # write changes
    with db.write_batch() as b:
        for blockn, value in references.items():
            print(blockn, value)
            b.put(blockn.to_bytes(4, "big"), cbor2.dumps(value))


def script_to_template(hex_script):
    bin_script = unhexlify(hex_script)
    try:
        script = CScript(bin_script)
        items = []
        for entry in script:
            if type(entry) == CScriptOp:
                if str(entry).startswith("CScriptOp("):
                    items.append(f"OP_UNKNOWN{int(entry)}")
                else:
                    items.append(str(entry))
            elif type(entry) == bytes:
                items.append("<data>")
            else:
                items.append(str(entry))
        return " ".join(items)
    except CScriptTruncatedPushDataError:
        return "[truncated-push-data]"
    except CScriptInvalidError:
        return "[invalid]"


def load_txtypes():
    global txtypes, examples
    try:
        with open("txtypes.cbor", "rb") as fp:
            txtypes = cbor2.load(fp)
    except FileNotFoundError:
        txtypes = {}

    try:
        with open("examples.cbor", "rb") as fp:
            examples = cbor2.load(fp)
    except FileNotFoundError:
        examples = {}


def get_or_set_txtype(txid, template):
    global txtypes, examples

    if not (examples.get(template)):
        examples[template] = txid
        with open("examples.cbor", "wb") as fp:
            cbor2.dump(examples, fp)

    if typn := txtypes.get(template):
        return typn
    else:
        typn = len(txtypes)
        txtypes[template] = typn
        with open("txtypes.cbor", "wb") as fp:
            cbor2.dump(txtypes, fp)
        return typn


try:
    main()
finally:
    db.close()
