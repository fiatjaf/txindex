from __future__ import absolute_import, division, print_function, unicode_literals
from pprint import pprint as pp

long = int
_bord = lambda x: x

import hashlib

import bitcoin.core
import bitcoin.core._bignum
import bitcoin.core.key
import bitcoin.core.serialize

# Importing everything for simplicity; note that we use __all__ at the end so
# we're not exporting the whole contents of the script module.
from bitcoin.core.script import (
    MAX_SCRIPT_SIZE,
    MAX_SCRIPT_OPCODES,
    MAX_SCRIPT_ELEMENT_SIZE,
    DISABLED_OPCODES,
    OPCODE_NAMES,
    CScript,
    FindAndDelete,
    OP_16,
    OP_1NEGATE,
    OP_PUSHDATA4,
    OP_1,
    OP_OVER,
    OP_DROP,
    OP_IF,
    OP_1ADD,
    OP_ADD,
    OP_BOOLAND,
    OP_BOOLOR,
    OP_NUMEQUAL,
    OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL,
    OP_GREATERTHAN,
    OP_GREATERTHANOREQUAL,
    OP_MIN,
    OP_MAX,
    OP_1SUB,
    OP_NEGATE,
    OP_ABS,
    OP_NOT,
    OP_0NOTEQUAL,
    OP_ELSE,
    OP_ROT,
    OP_SHA1,
    OP_SHA256,
    OP_TUCK,
    OP_TOALTSTACK,
    OP_SIZE,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY,
    OP_ENDIF,
    OP_SUB,
    OP_SWAP,
    OP_2SWAP,
    OP_HASH256,
    OP_HASH160,
    OP_LESSTHAN,
    OP_LESSTHANOREQUAL,
    OP_WITHIN,
    OP_3DUP,
    OP_2ROT,
    OP_2OVER,
    OP_CODESEPARATOR,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_DEPTH,
    OP_NOTIF,
    OP_IFDUP,
    OP_NIP,
    OP_NOP,
    OP_NOP1,
    OP_FROMALTSTACK,
    OP_2DUP,
    OP_2DROP,
    OP_VERIFY,
    OP_RETURN,
    OP_RIPEMD160,
    OP_ROLL,
    OP_PICK,
    OP_NOP10,
)

MAX_NUM_SIZE = 4
MAX_STACK_ITEMS = 1000


class EvalScriptError(Exception):
    pass


def _CastToBigNum(s):
    v = bitcoin.core._bignum.vch2bn(s)
    if len(s) > MAX_NUM_SIZE:
        raise EvalScriptError
    return v


def _CastToBool(s):
    for i in range(len(s)):
        sv = _bord(s[i])
        if sv != 0:
            if (i == (len(s) - 1)) and (sv == 0x80):
                return False
            return True

    return False


def _CheckSig(sig, pubkey, script):
    if len(sig) > 100 or len(sig) < 50:
        return False
    if len(pubkey) > 100 or len(pubkey) < 50:
        return False
    return True


def _CheckMultiSig(opcode, script, stack, nOpCount):
    i = 1
    if len(stack) < i:
        raise EvalScriptError

    keys_count = _CastToBigNum(stack[-i])
    if keys_count < 0 or keys_count > 20:
        raise EvalScriptError
    i += 1
    ikey = i
    i += keys_count
    nOpCount[0] += keys_count
    if nOpCount[0] > MAX_SCRIPT_OPCODES:
        raise EvalScriptError
    if len(stack) < i:
        raise EvalScriptError

    sigs_count = _CastToBigNum(stack[-i])
    if sigs_count < 0 or sigs_count > keys_count:
        raise EvalScriptError

    i += 1
    isig = i
    i += sigs_count
    if len(stack) < i - 1:
        raise EvalScriptError
    elif len(stack) < i:
        raise EvalScriptError

    # Drop the signature, since there's no way for a signature to sign itself
    #
    # Of course, this can only come up in very contrived cases now that
    # scriptSig and scriptPubKey are processed separately.
    for k in range(sigs_count):
        sig = stack[-isig - k]
        script = FindAndDelete(script, CScript([sig]))

    success = True

    while success and sigs_count > 0:
        sig = stack[-isig]
        pubkey = stack[-ikey]

        if _CheckSig(sig, pubkey, script):
            isig += 1
            sigs_count -= 1

        ikey += 1
        keys_count -= 1

        if sigs_count > keys_count:
            success = False

            # with VERIFY bail now before we modify the stack
            if opcode == OP_CHECKMULTISIGVERIFY:
                raise EvalScriptError

    while i > 1:
        stack.pop()
        i -= 1

    stack.pop()

    if opcode == OP_CHECKMULTISIG:
        if success:
            stack.append(b"\x01")
        else:
            # FIXME: this is incorrect, but not caught by existing
            # test cases
            stack.append(b"\x00")


# OP_2MUL and OP_2DIV are *not* included in this list as they are disabled
_ISA_UNOP = {
    OP_1ADD,
    OP_1SUB,
    OP_NEGATE,
    OP_ABS,
    OP_NOT,
    OP_0NOTEQUAL,
}


def _UnaryOp(opcode, stack):
    if len(stack) < 1:
        raise EvalScriptError
    bn = _CastToBigNum(stack[-1])
    stack.pop()

    if opcode == OP_1ADD:
        bn += 1

    elif opcode == OP_1SUB:
        bn -= 1

    elif opcode == OP_NEGATE:
        bn = -bn

    elif opcode == OP_ABS:
        if bn < 0:
            bn = -bn

    elif opcode == OP_NOT:
        bn = long(bn == 0)

    elif opcode == OP_0NOTEQUAL:
        bn = long(bn != 0)

    else:
        raise AssertionError("Unknown unary opcode encountered; this should not happen")

    stack.append(bitcoin.core._bignum.bn2vch(bn))


# OP_LSHIFT and OP_RSHIFT are *not* included in this list as they are disabled
_ISA_BINOP = {
    OP_ADD,
    OP_SUB,
    OP_BOOLAND,
    OP_BOOLOR,
    OP_NUMEQUAL,
    OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL,
    OP_LESSTHAN,
    OP_GREATERTHAN,
    OP_LESSTHANOREQUAL,
    OP_GREATERTHANOREQUAL,
    OP_MIN,
    OP_MAX,
}


def _BinOp(opcode, stack):
    if len(stack) < 2:
        raise EvalScriptError

    bn2 = _CastToBigNum(stack[-1])
    bn1 = _CastToBigNum(stack[-2])

    # We don't pop the stack yet so that OP_NUMEQUALVERIFY can raise
    # VerifyOpFailedError with a correct stack.

    if opcode == OP_ADD:
        bn = bn1 + bn2

    elif opcode == OP_SUB:
        bn = bn1 - bn2

    elif opcode == OP_BOOLAND:
        bn = long(bn1 != 0 and bn2 != 0)

    elif opcode == OP_BOOLOR:
        bn = long(bn1 != 0 or bn2 != 0)

    elif opcode == OP_NUMEQUAL:
        bn = long(bn1 == bn2)

    elif opcode == OP_NUMEQUALVERIFY:
        bn = long(bn1 == bn2)
        if not bn:
            raise EvalScriptError
        else:
            # No exception, so time to pop the stack
            stack.pop()
            stack.pop()
            return

    elif opcode == OP_NUMNOTEQUAL:
        bn = long(bn1 != bn2)

    elif opcode == OP_LESSTHAN:
        bn = long(bn1 < bn2)

    elif opcode == OP_GREATERTHAN:
        bn = long(bn1 > bn2)

    elif opcode == OP_LESSTHANOREQUAL:
        bn = long(bn1 <= bn2)

    elif opcode == OP_GREATERTHANOREQUAL:
        bn = long(bn1 >= bn2)

    elif opcode == OP_MIN:
        if bn1 < bn2:
            bn = bn1
        else:
            bn = bn2

    elif opcode == OP_MAX:
        if bn1 > bn2:
            bn = bn1
        else:
            bn = bn2

    else:
        raise AssertionError("Unknown binop opcode encountered; this should not happen")

    stack.pop()
    stack.pop()
    stack.append(bitcoin.core._bignum.bn2vch(bn))


def _CheckExec(vfExec):
    for b in vfExec:
        if not b:
            return False
    return True


def eval_script(stack, scriptIn, debug=False):
    if len(scriptIn) > MAX_SCRIPT_SIZE:
        raise EvalScriptError(
            "script too large; got %d bytes; maximum %d bytes"
            % (len(scriptIn), MAX_SCRIPT_SIZE),
            stack=stack,
            scriptIn=scriptIn,
        )

    altstack = []
    vfExec = []
    pbegincodehash = 0
    nOpCount = [0]

    if debug:
        print("-- start script --")

    for (sop, sop_data, sop_pc) in scriptIn.raw_iter():
        fExec = _CheckExec(vfExec)

        if debug and (sop <= OP_PUSHDATA4 or fExec or (OP_IF <= sop <= OP_ENDIF)):
            pp([s.hex() if type(s) == bytes else s for s in stack])
            print(OPCODE_NAMES.get(sop, sop))

        if sop in DISABLED_OPCODES:
            raise EvalScriptError

        if sop > OP_16:
            nOpCount[0] += 1
            if nOpCount[0] > MAX_SCRIPT_OPCODES:
                raise EvalScriptError

        def check_args(n):
            if len(stack) < n:
                raise EvalScriptError

        if sop <= OP_PUSHDATA4:
            if len(sop_data) > MAX_SCRIPT_ELEMENT_SIZE:
                raise EvalScriptError

            elif fExec:
                stack.append(sop_data)
                continue

        elif fExec or (OP_IF <= sop <= OP_ENDIF):

            if sop == OP_1NEGATE or ((sop >= OP_1) and (sop <= OP_16)):
                v = sop - (OP_1 - 1)
                stack.append(bitcoin.core._bignum.bn2vch(v))

            elif sop in _ISA_BINOP:
                _BinOp(sop, stack)

            elif sop in _ISA_UNOP:
                _UnaryOp(sop, stack)

            elif sop == OP_2DROP:
                check_args(2)
                stack.pop()
                stack.pop()

            elif sop == OP_2DUP:
                check_args(2)
                v1 = stack[-2]
                v2 = stack[-1]
                stack.append(v1)
                stack.append(v2)

            elif sop == OP_2OVER:
                check_args(4)
                v1 = stack[-4]
                v2 = stack[-3]
                stack.append(v1)
                stack.append(v2)

            elif sop == OP_2ROT:
                check_args(6)
                v1 = stack[-6]
                v2 = stack[-5]
                del stack[-6]
                del stack[-5]
                stack.append(v1)
                stack.append(v2)

            elif sop == OP_2SWAP:
                check_args(4)
                tmp = stack[-4]
                stack[-4] = stack[-2]
                stack[-2] = tmp

                tmp = stack[-3]
                stack[-3] = stack[-1]
                stack[-1] = tmp

            elif sop == OP_3DUP:
                check_args(3)
                v1 = stack[-3]
                v2 = stack[-2]
                v3 = stack[-1]
                stack.append(v1)
                stack.append(v2)
                stack.append(v3)

            elif sop == OP_CHECKMULTISIG or sop == OP_CHECKMULTISIGVERIFY:
                tmpScript = CScript(scriptIn[pbegincodehash:])
                _CheckMultiSig(sop, tmpScript, stack, nOpCount)

            elif sop == OP_CHECKSIG or sop == OP_CHECKSIGVERIFY:
                check_args(2)
                vchPubKey = stack[-1]
                vchSig = stack[-2]
                tmpScript = CScript(scriptIn[pbegincodehash:])

                # Drop the signature, since there's no way for a signature to sign itself
                #
                # Of course, this can only come up in very contrived cases now that
                # scriptSig and scriptPubKey are processed separately.
                tmpScript = FindAndDelete(tmpScript, CScript([vchSig]))

                ok = _CheckSig(vchSig, vchPubKey, tmpScript)
                if not ok and sop == OP_CHECKSIGVERIFY:
                    raise EvalScriptError

                else:
                    stack.pop()
                    stack.pop()

                    if ok:
                        if sop != OP_CHECKSIGVERIFY:
                            stack.append(b"\x01")
                    else:
                        # FIXME: this is incorrect, but not caught by existing
                        # test cases
                        stack.append(b"\x00")

            elif sop == OP_CODESEPARATOR:
                pbegincodehash = sop_pc

            elif sop == OP_DEPTH:
                bn = len(stack)
                stack.append(bitcoin.core._bignum.bn2vch(bn))

            elif sop == OP_DROP:
                check_args(1)
                stack.pop()

            elif sop == OP_DUP:
                check_args(1)
                v = stack[-1]
                stack.append(v)

            elif sop == OP_ELSE:
                if len(vfExec) == 0:
                    raise EvalScriptError
                vfExec[-1] = not vfExec[-1]

            elif sop == OP_ENDIF:
                if len(vfExec) == 0:
                    raise EvalScriptError
                vfExec.pop()

            elif sop == OP_EQUAL:
                check_args(2)
                v1 = stack.pop()
                v2 = stack.pop()

                if v1 == v2:
                    stack.append(b"\x01")
                else:
                    stack.append(b"")

            elif sop == OP_EQUALVERIFY:
                check_args(2)
                v1 = stack[-1]
                v2 = stack[-2]

                if v1 == v2:
                    stack.pop()
                    stack.pop()
                else:
                    raise EvalScriptError

            elif sop == OP_FROMALTSTACK:
                if len(altstack) < 1:
                    raise EvalScriptError
                v = altstack.pop()
                stack.append(v)

            elif sop == OP_HASH160:
                check_args(1)
                stack.append(bitcoin.core.serialize.Hash160(stack.pop()))

            elif sop == OP_HASH256:
                check_args(1)
                stack.append(bitcoin.core.serialize.Hash(stack.pop()))

            elif sop == OP_IF or sop == OP_NOTIF:
                val = False

                if fExec:
                    check_args(1)
                    vch = stack.pop()
                    val = _CastToBool(vch)
                    if sop == OP_NOTIF:
                        val = not val

                vfExec.append(val)

            elif sop == OP_IFDUP:
                check_args(1)
                vch = stack[-1]
                if _CastToBool(vch):
                    stack.append(vch)

            elif sop == OP_NIP:
                check_args(2)
                del stack[-2]

            elif sop == OP_NOP:
                pass

            elif sop >= OP_NOP1 and sop <= OP_NOP10:
                pass

            elif sop == OP_OVER:
                check_args(2)
                vch = stack[-2]
                stack.append(vch)

            elif sop == OP_PICK or sop == OP_ROLL:
                check_args(2)
                n = _CastToBigNum(stack.pop())
                if n < 0 or n >= len(stack):
                    raise EvalScriptError
                vch = stack[-n - 1]
                if sop == OP_ROLL:
                    del stack[-n - 1]
                stack.append(vch)

            elif sop == OP_RETURN:
                raise EvalScriptError

            elif sop == OP_RIPEMD160:
                check_args(1)

                h = hashlib.new("ripemd160")
                h.update(stack.pop())
                stack.append(h.digest())

            elif sop == OP_ROT:
                check_args(3)
                tmp = stack[-3]
                stack[-3] = stack[-2]
                stack[-2] = tmp

                tmp = stack[-2]
                stack[-2] = stack[-1]
                stack[-1] = tmp

            elif sop == OP_SIZE:
                check_args(1)
                bn = len(stack[-1])
                stack.append(bitcoin.core._bignum.bn2vch(bn))

            elif sop == OP_SHA1:
                check_args(1)
                stack.append(hashlib.sha1(stack.pop()).digest())

            elif sop == OP_SHA256:
                check_args(1)
                stack.append(hashlib.sha256(stack.pop()).digest())

            elif sop == OP_SWAP:
                check_args(2)
                tmp = stack[-2]
                stack[-2] = stack[-1]
                stack[-1] = tmp

            elif sop == OP_TOALTSTACK:
                check_args(1)
                v = stack.pop()
                altstack.append(v)

            elif sop == OP_TUCK:
                check_args(2)
                vch = stack[-1]
                stack.insert(len(stack) - 2, vch)

            elif sop == OP_VERIFY:
                check_args(1)
                v = _CastToBool(stack[-1])
                if v:
                    stack.pop()
                else:
                    raise EvalScriptError

            elif sop == OP_WITHIN:
                check_args(3)
                bn3 = _CastToBigNum(stack[-1])
                bn2 = _CastToBigNum(stack[-2])
                bn1 = _CastToBigNum(stack[-3])
                stack.pop()
                stack.pop()
                stack.pop()
                v = (bn2 <= bn1) and (bn1 < bn3)
                if v:
                    stack.append(b"\x01")
                else:
                    # FIXME: this is incorrect, but not caught by existing
                    # test cases
                    stack.append(b"\x00")

            else:
                raise EvalScriptError

        # size limits
        if len(stack) + len(altstack) > MAX_STACK_ITEMS:
            raise EvalScriptError

    # Unterminated IF/NOTIF/ELSE block
    if len(vfExec):
        raise EvalScriptError

    if debug:
        pp([s.hex() if type(s) == bytes else s for s in stack])
        print("-- end --")

    return stack


__all__ = "eval_script"
