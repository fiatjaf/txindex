from binascii import unhexlify
from bitcoin.core.script import (
    OP_CHECKSIGVERIFY,
    OP_EQUAL,
    OP_NOTIF,
    OP_SWAP,
    OP_SIZE,
    OP_CHECKLOCKTIMEVERIFY,
    OP_IF,
    OP_ELSE,
    OP_ENDIF,
    OP_DROP,
    OP_CHECKSEQUENCEVERIFY,
    OP_EQUALVERIFY,
    OP_CHECKMULTISIG,
    OP_DUP,
    OP_HASH160,
    OP_CHECKSIG,
    OP_VERIFY,
    CScript,
    CScriptOp,
)
from naive_eval import eval_script

s = eval_script([], CScript([]))
print("blank is fine", len(s))

n = CScriptOp.encode_op_pushdata(b"qowie")
s = eval_script([n], CScript([n, OP_EQUALVERIFY]))
print("equalverify is fine", len(s))

s = eval_script(
    [
        CScriptOp.encode_op_pushdata(
            unhexlify(
                "30450220377bf4cab9bbdb219f1b0cca56f4a39fbf787d6fa9d04e248101d498de991d30022100b8e0c72dfab9a0d88eb2703c62e0e57ab2cb906e8f156b7641c2f0e24b8bba2b01"
            )
        ),
    ],
    CScript(
        [
            CScriptOp.encode_op_pushdata(
                unhexlify(
                    "045e9392308b08d0d663961463b6cd056a66b757a2ced9dde197c21362360237f231b80ea66315898969f5c079f0ba3fc1c0661ed8c853ad15043f22f2b7779c95"
                )
            ),
            OP_CHECKSIGVERIFY,
        ]
    ),
)
print("checksigverify is fine", len(s))

s = eval_script(
    [
        CScriptOp.encode_op_pushdata(
            unhexlify(
                "30450220377bf4cab9bbdb219f1b0cca56f4a39fbf787d6fa9d04e248101d498de991d30022100b8e0c72dfab9a0d88eb2703c62e0e57ab2cb906e8f156b7641c2f0e24b8bba2b01"
            )
        ),
    ],
    CScript(
        [
            CScriptOp.encode_op_pushdata(
                unhexlify(
                    "045e9392308b08d0d663961463b6cd056a66b757a2ced9dde197c21362360237f231b80ea66315898969f5c079f0ba3fc1c0661ed8c853ad15043f22f2b7779c95"
                )
            ),
            OP_CHECKSIG,
            OP_VERIFY,
        ]
    ),
)
print("checksig verify is fine", len(s))

eval_script(
    [
        unhexlify(
            "3044022017cd8c4467f0b5f463b963b2d30421553b98f37356f042a4bf99570818bc2fcf02200ff7f165fcc7e67654f13ce7693fef1ccc160426f8c3b24afab7cd9fa064e8a501"
        ),
        unhexlify(
            "045e9392308b08d0d663961463b6cd056a66b757a2ced9dde197c21362360237f231b80ea66315898969f5c079f0ba3fc1c0661ed8c853ad15043f22f2b7779c95"
        ),
    ],
    CScript(
        [
            OP_DUP,
            OP_HASH160,
            unhexlify("33935419187fd5a4dfd850a08f388a477e98016d"),
            OP_EQUALVERIFY,
            OP_CHECKSIG,
        ]
    ),
)
print("p2pkh is fine", len(s))

s = eval_script(
    [
        unhexlify(
            "304402201be07b2c2ec2355b97646ba90598a2e9c4cab113abebdf6e2c7da56266341ccc022079908afb43b348501a443368af70875bb1817abe154f5c9df39b8854172e5f7501"
        ),
        unhexlify("0229b6a22bbd81e311ede51817dbdff66d106d26f851f3b09f6493f8500b123a8f"),
    ],
    CScript(
        [OP_HASH160, unhexlify("088ba1e460e92be4f4e97fb799a5fb4085cd6bcf"), OP_EQUAL]
    ),
)
print("p2sh is fine", len(s))

s = eval_script(
    [
        0,
        unhexlify(
            "3045022100e4492aeff1dd6c349685905e26ea0738a05b24dc6e9ad4f9249d3bce0d902b3702201b4d3eb321b2d1fe0431136120ada464b4a12885edadfa9c16fa8e682568b77d01"
        ),
        unhexlify(
            "3045022100f4b8d74ecaddd613258909c6eb06a1e2fc24e3d52b9e058a0a2346d52d58f0bc022006641c7335eb8379c840a9ab50bbfd3d8ff3c4c0b12e7b087703d7963adc1b2e01"
        ),
    ],
    CScript(
        [
            2,
            unhexlify(
                "039ae180d72e34a09d052547f9c25b4aec0982de33e35f02016f67ff7d170061df"
            ),
            unhexlify(
                "02f7fa3bf5b48387a28e994ef1c183d7ab8da3943672c252d6864a366b7fbd83f6"
            ),
            2,
            OP_CHECKMULTISIG,
        ]
    ),
)
print("2-of-2 multisig is fine", len(s))

s = eval_script(
    [
        0,
        unhexlify(
            "3045022100e4492aeff1dd6c349685905e26ea0738a05b24dc6e9ad4f9249d3bce0d902b3702201b4d3eb321b2d1fe0431136120ada464b4a12885edadfa9c16fa8e682568b77d01"
        ),
    ],
    CScript(
        [
            1,
            unhexlify(
                "039ae180d72e34a09d052547f9c25b4aec0982de33e35f02016f67ff7d170061df"
            ),
            unhexlify(
                "02f7fa3bf5b48387a28e994ef1c183d7ab8da3943672c252d6864a366b7fbd83f6"
            ),
            2,
            OP_CHECKMULTISIG,
        ]
    ),
)
print("1-of-2 multisig is fine", len(s))

s = eval_script(
    [
        0,
        unhexlify(
            "3045022100e4492aeff1dd6c349685905e26ea0738a05b24dc6e9ad4f9249d3bce0d902b3702201b4d3eb321b2d1fe0431136120ada464b4a12885edadfa9c16fa8e682568b77d01"
        ),
        unhexlify(
            "3045022100f4b8d74ecaddd613258909c6eb06a1e2fc24e3d52b9e058a0a2346d52d58f0bc022006641c7335eb8379c840a9ab50bbfd3d8ff3c4c0b12e7b087703d7963adc1b2e01"
        ),
    ],
    CScript(
        [
            2,
            unhexlify(
                "039ae180d72e34a09d052547f9c25b4aec0982de33e35f02016f67ff7d170061df"
            ),
            unhexlify(
                "02f7fa3bf5b48387a28e994ef1c183d7ab8da3943672c252d6864a366b7fbd83f6"
            ),
            unhexlify(
                "029846329846329486239487622323d7ab8da3943672c252d6864a366b7fbd83f6"
            ),
            3,
            OP_CHECKMULTISIG,
        ]
    ),
)
print("2-of-3 multisig is fine", len(s))

s = eval_script(
    [
        unhexlify(
            "30450221009a07202a9c52ddcb4b1049e635b3cd08b0708ca5989f9e7f980455f8dcb190e20220595df5ff9db901e3e5c835fd8c94a92edf6428e15595ecd3d76a03cbebb268af01"
        ),
        unhexlify("01"),
    ],
    CScript(
        [
            OP_IF,
            unhexlify(
                "02918e23e930f04e1d1dbe52abd1dac992b9c042fa62c959d346142ab705d354c3"
            ),
            OP_ELSE,
            144,
            OP_CHECKSEQUENCEVERIFY,
            OP_DROP,
            unhexlify(
                "02446380607dd0524203cf30e19051bf02d82e65619df8deaf1e3d2998ee964b72"
            ),
            OP_ENDIF,
            OP_CHECKSIG,
        ]
    ),
)
print("commitment transaction is fine with penalty", len(s))

s = eval_script(
    [
        unhexlify(
            "304402202555443258ef15982509e7280121de4965cfdcc9d87f7d0d217bb173d4879a28022003ff853cca248d9a2a41779cfc6e6c2abc587370dccdaf2072a2f9d764a37a5c01"
        ),
        unhexlify("00"),
    ],
    CScript(
        [
            OP_IF,
            unhexlify(
                "033a49430b4457a5bdd1fed5dbacf47cf2363d45c851b787684293c32011097e2c"
            ),
            OP_ELSE,
            144,
            OP_CHECKSEQUENCEVERIFY,
            OP_DROP,
            unhexlify(
                "02446380607dd0524203cf30e19051bf02d82e65619df8deaf1e3d2998ee964b72"
            ),
            OP_ENDIF,
            OP_CHECKSIG,
        ]
    ),
)
print("commitment transaction is fine without penalty", len(s))

s = eval_script(
    [
        unhexlify(
            "30450221009f119aa2a8ea840b52ef6478b8f03e17fe13caa21dcca9aa59d1f1d2d3409b410220498bcf40544093c362ffba707c557a5cdc38514840c7c6cdd76bf16ed8af01b901"
        ),
        unhexlify("00"),
    ],
    CScript(
        [
            OP_DUP,
            OP_HASH160,
            unhexlify("69e1f11c21d297f22549a9cbd7e4c565268426f1"),
            OP_EQUAL,
            OP_IF,
            OP_CHECKSIG,
            OP_ELSE,
            unhexlify(
                "026fa30791854be62d5ece2c6f26c330928f626922ffdaa522a31bebeef1735c69"
            ),
            OP_SWAP,
            OP_SIZE,
            32,
            OP_EQUAL,
            OP_IF,
            OP_HASH160,
            unhexlify("af51b4c970ef93da62cdd40fbaf49afa1300de9a"),
            OP_EQUALVERIFY,
            2,
            OP_SWAP,
            unhexlify(
                "03b7debcd4f47e027877e9e140c3f567e09e75ca058785107c2063673ac8e08046"
            ),
            2,
            OP_CHECKMULTISIG,
            OP_ELSE,
            OP_DROP,
            596353,
            OP_CHECKLOCKTIMEVERIFY,
            OP_DROP,
            OP_CHECKSIG,
            OP_ENDIF,
            OP_ENDIF,
        ]
    ),
)
print("rescued htlc is fine", len(s))

s = eval_script(
    [
        0,
        unhexlify(
            "30450221009f119aa2a8ea840b52ef6478b8f03e17fe13caa21dcca9aa59d1f1d2d3409b410220498bcf40544093c362ffba707c557a5cdc38514840c7c6cdd76bf16ed8af01b901"
        ),
        unhexlify(
            "30450221009f119aa2a8ea840b52ef6478b8f03e17fe13caa21dcca9aa59d1f1d2d3409b410220498bcf40544093c362ffba707c557a5cdc38514840c7c6cdd76bf16ed8af01b901"
        ),
        unhexlify("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
    ],
    CScript(
        [
            OP_DUP,
            OP_HASH160,
            unhexlify("af51b4c970ef93da62cdd40fbaf49afa1300de9a"),
            OP_EQUAL,
            OP_IF,
            OP_CHECKSIG,
            OP_ELSE,
            unhexlify(
                "026fa30791854be62d5ece2c6f26c330928f626922ffdaa522a31bebeef1735c69"
            ),
            OP_SWAP,
            OP_SIZE,
            32,
            OP_EQUAL,
            OP_IF,
            OP_HASH160,
            unhexlify("62da96bf095449112d5650282c73856127ac5052"),
            OP_EQUALVERIFY,
            2,
            OP_SWAP,
            unhexlify(
                "03b7debcd4f47e027877e9e140c3f567e09e75ca058785107c2063673ac8e08046"
            ),
            2,
            OP_CHECKMULTISIG,
            OP_ELSE,
            OP_DROP,
            596353,
            OP_CHECKLOCKTIMEVERIFY,
            OP_DROP,
            OP_CHECKSIG,
            OP_ENDIF,
            OP_ENDIF,
        ]
    ),
)
print("fulfilled htlc is fine", len(s))

s = eval_script(
    [
        unhexlify("00"),
        unhexlify(
            "3045022100d3151806021a58de89535b7870eb258e89dc70f015156533a555afb661941536022025f1a9bbe816ef0ccff3ed477e9f10e043b15163224d05c3f511940483f721db01"
        ),
        unhexlify(
            "3045022100b3c746ac9bb7c8879837fec2bb46c3972b55a0e3efde151f1429a0e798f95fad02207d8795fb8173531f2625906c3d5c2898c63639571744266d220a91007fa3c69e01"
        ),
        unhexlify("00"),
    ],
    CScript(
        [
            OP_DUP,
            OP_HASH160,
            unhexlify("0b3c74f5c3c4358b08a2381894b0031803a6c459"),
            OP_EQUAL,
            OP_IF,
            OP_CHECKSIG,
            OP_ELSE,
            unhexlify(
                "03d32fba8616f396246154f1ff39de566270d71e63a33c4e6245de0dd005ab0cfb"
            ),
            OP_SWAP,
            OP_SIZE,
            32,
            OP_EQUAL,
            OP_NOTIF,
            OP_DROP,
            2,
            OP_SWAP,
            unhexlify(
                "036de0c5399a567ead4a66576e8bfbfb1c975ba7fa817bdb78d16f8446185362db"
            ),
            2,
            OP_CHECKMULTISIG,
            OP_ELSE,
            OP_HASH160,
            unhexlify("6b5ebca153f508ed4b15c44776ee13ac800dbb77"),
            OP_EQUALVERIFY,
            OP_CHECKSIG,
            OP_ENDIF,
            OP_ENDIF,
        ]
    ),
)
print("other htlc is fine, not fulfilled", len(s))
