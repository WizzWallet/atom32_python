from bitcoinutils.setup import setup
from bitcoinutils.keys import P2pkhAddress, P2trAddress, P2shAddress, P2wpkhAddress
from atom32.conversion import encode

from enum import Enum
import hashlib
import struct
from typing import Optional, Callable, Union


class AddressType(Enum):
    p2tr = 'p2tr'
    p2pkh = 'p2pkh'
    p2sh_p2wpkh = 'p2sh_p2wpkh'
    p2wpkh = 'p2wpkh'
    unknown = 'unknown'


def get_address_type(address: str):
    if address.startswith('bc1q'):
        return AddressType.p2wpkh
    if address.startswith('bc1p'):
        return AddressType.p2tr
    if address.startswith('1'):
        return AddressType.p2pkh
    if address.startswith('3'):
        return AddressType.p2sh_p2wpkh
    # Testnet
    if address.startswith('tb1q'):
        return AddressType.p2wpkh
    if address.startswith('tb1p'):
        return AddressType.p2tr
    if address.startswith('m') or address.startswith('n'):
        return AddressType.p2pkh
    if address.startswith('2'):
        return AddressType.p2sh_p2wpkh
    return AddressType.unknown


def detect_address_type_to_script_hash(address: str, network: str = "mainnet"):
    setup(network)
    address_type = get_address_type(address)
    if address_type == AddressType.p2tr:
        a = P2trAddress(address)
    elif address_type == AddressType.p2wpkh:
        a = P2wpkhAddress(address)
    elif address_type == AddressType.p2pkh:
        a = P2pkhAddress(address)
    elif address_type == AddressType.p2sh_p2wpkh:
        a = P2shAddress(address)
    else:
        raise Exception('unrecognized address')
    script = a.to_script_pub_key()
    return {
        'output': script.to_bytes(),
        'scripthash': hashlib.sha256(script.to_bytes()).digest()[::-1].hex(),
        'address': address
    }


class OPPushDataGeneric:
    def __init__(self, pushlen: Callable = None):
        if pushlen is not None:
            self.check_data_len = pushlen

    @classmethod
    def check_data_len(cls, datalen: int) -> bool:
        # Opcodes below OP_PUSHDATA4 all just push data onto stack, and are equivalent.
        return OpCodes.OP_PUSHDATA4 >= datalen >= 0

    @classmethod
    def is_instance(cls, item):
        # accept objects that are instances of this class
        # or other classes that are subclasses
        return isinstance(item, cls) \
            or (isinstance(item, type) and issubclass(item, cls))


class OPGeneric:
    def __init__(self, matcher: Callable = None):
        if matcher is not None:
            self.matcher = matcher

    def match(self, op) -> bool:
        return self.matcher(op)

    @classmethod
    def is_instance(cls, item):
        # accept objects that are instances of this class
        # or other classes that are subclasses
        return isinstance(item, cls) \
            or (isinstance(item, type) and issubclass(item, cls))


def match_script_against_template(script, template: list) -> bool:
    """Returns whether 'script' matches 'template'."""
    if script is None:
        return False
    # optionally decode script now:
    if isinstance(script, (bytes, bytearray)):
        try:
            script = [x for x in script_get_op(script)]
        except MalformedBitcoinScript:
            return False

    if len(script) != len(template):
        return False
    for i in range(len(script)):
        template_item = template[i]
        script_item = script[i]
        if OPPushDataGeneric.is_instance(template_item) and template_item.check_data_len(script_item[0]):
            continue
        if OPGeneric.is_instance(template_item) and template_item.match(script_item[0]):
            continue
        if template_item != script_item[0]:
            return False
    return True


class MalformedBitcoinScript(Exception):
    pass


def script_get_op(_bytes: bytes):
    i = 0
    while i < len(_bytes):
        vch = None
        opcode = _bytes[i]
        i += 1
        if opcode <= OpCodes.OP_PUSHDATA4:
            n_size = opcode
            if opcode == OpCodes.OP_PUSHDATA1:
                try:
                    n_size = _bytes[i]
                except IndexError:
                    raise MalformedBitcoinScript()
                i += 1
            elif opcode == OpCodes.OP_PUSHDATA2:
                try:
                    (n_size,) = struct.unpack_from('<H', _bytes, i)
                except struct.error:
                    raise MalformedBitcoinScript()
                i += 2
            elif opcode == OpCodes.OP_PUSHDATA4:
                try:
                    (n_size,) = struct.unpack_from('<I', _bytes, i)
                except struct.error:
                    raise MalformedBitcoinScript()
                i += 4
            vch = _bytes[i:i + n_size]
            i += n_size

        yield opcode, vch, i


class Enumeration:
    def __init__(self, name: str, enum_list: list):
        self.__doc__ = name

        lookup = {}
        reverse_lookup = {}
        i = 0
        unique_names = set()
        unique_values = set()
        for x in enum_list:
            if isinstance(x, tuple):
                x, i = x
            if not isinstance(x, str):
                raise EnumError("enum name {} not a string".format(x))
            if not isinstance(i, int):
                raise EnumError("enum value {} not an integer".format(i))
            if x in unique_names:
                raise EnumError("enum name {} not unique".format(x))
            if i in unique_values:
                raise EnumError("enum value {} not unique".format(x))
            unique_names.add(x)
            unique_values.add(i)
            lookup[x] = i
            reverse_lookup[i] = x
            i = i + 1
        self.lookup = lookup
        self.reverseLookup = reverse_lookup

    def __getattr__(self, attr):
        result = self.lookup.get(attr)
        if result is None:
            raise AttributeError('enumeration has no member {}'.format(attr))
        return result

    def whatis(self, value):
        return self.reverseLookup[value]


class EnumError(Exception):
    pass


OpCodes = Enumeration("Opcodes", [
    ("OP_0", 0), ("OP_PUSHDATA1", 76),
    "OP_PUSHDATA2", "OP_PUSHDATA4", "OP_1NEGATE",
    "OP_RESERVED",
    "OP_1", "OP_2", "OP_3", "OP_4", "OP_5", "OP_6", "OP_7", "OP_8",
    "OP_9", "OP_10", "OP_11", "OP_12", "OP_13", "OP_14", "OP_15", "OP_16",
    "OP_NOP", "OP_VER", "OP_IF", "OP_NOTIF", "OP_VERIF", "OP_VERNOTIF",
    "OP_ELSE", "OP_ENDIF", "OP_VERIFY", "OP_RETURN",
    "OP_TOALTSTACK", "OP_FROMALTSTACK", "OP_2DROP", "OP_2DUP", "OP_3DUP",
    "OP_2OVER", "OP_2ROT", "OP_2SWAP", "OP_IFDUP", "OP_DEPTH", "OP_DROP",
    "OP_DUP", "OP_NIP", "OP_OVER", "OP_PICK", "OP_ROLL", "OP_ROT",
    "OP_SWAP", "OP_TUCK",
    "OP_CAT", "OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_SIZE",
    "OP_INVERT", "OP_AND", "OP_OR", "OP_XOR", "OP_EQUAL", "OP_EQUALVERIFY",
    "OP_RESERVED1", "OP_RESERVED2",
    "OP_1ADD", "OP_1SUB", "OP_2MUL", "OP_2DIV", "OP_NEGATE", "OP_ABS",
    "OP_NOT", "OP_0NOTEQUAL", "OP_ADD", "OP_SUB", "OP_MUL", "OP_DIV", "OP_MOD",
    "OP_LSHIFT", "OP_RSHIFT", "OP_BOOLAND", "OP_BOOLOR", "OP_NUMEQUAL",
    "OP_NUMEQUALVERIFY", "OP_NUMNOTEQUAL", "OP_LESSTHAN", "OP_GREATERTHAN",
    "OP_LESSTHANOREQUAL", "OP_GREATERTHANOREQUAL", "OP_MIN", "OP_MAX",
    "OP_WITHIN",
    "OP_RIPEMD160", "OP_SHA1", "OP_SHA256", "OP_HASH160", "OP_HASH256",
    "OP_CODESEPARATOR", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKMULTISIG",
    "OP_CHECKMULTISIGVERIFY",
    "OP_NOP1",
    "OP_CHECKLOCKTIMEVERIFY", "OP_CHECKSEQUENCEVERIFY"
])


def assert_bytes(*args):
    """
    porting helper, assert args type
    """
    try:
        for x in args:
            assert isinstance(x, (bytes, bytearray))
    except Exception:
        print('assert bytes failed', list(map(type, args)))
        raise


__b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
assert len(__b58chars) == 58

__b43chars = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'
assert len(__b43chars) == 43


def base_encode(v: bytes, *, base: int) -> str:
    """ encode v, which is a string of bytes, to base58."""
    assert_bytes(v)
    if base not in (58, 43):
        raise ValueError('not supported base: {}'.format(base))
    chars = __b58chars
    if base == 43:
        chars = __b43chars

    origlen = len(v)
    v = v.lstrip(b'\x00')
    newlen = len(v)

    num = int.from_bytes(v, byteorder='big')
    string = b""
    while num:
        num, idx = divmod(num, base)
        string = chars[idx:idx + 1] + string

    result = chars[0:1] * (origlen - newlen) + string
    return result.decode('ascii')


def to_bytes(something, encoding: str = 'utf8') -> bytes:
    """
    cast string to bytes() like object, but for python2 support it's bytearray copy
    """
    if isinstance(something, bytes):
        return something
    if isinstance(something, str):
        return something.encode(encoding)
    elif isinstance(something, bytearray):
        return bytes(something)
    else:
        raise TypeError("Not a string or bytes like object")


def sha256(x: Union[bytes, str]) -> bytes:
    x = to_bytes(x, 'utf8')
    return bytes(hashlib.sha256(x).digest())


def sha256d(x: Union[bytes, str]) -> bytes:
    x = to_bytes(x, 'utf8')
    out = bytes(sha256(sha256(x)))
    return out


def hash160_to_b58_address(h160: bytes, address_type: int) -> str:
    s = bytes([address_type]) + h160
    s = s + sha256d(s)[0:4]
    return base_encode(s, base=58)


def get_addr_type_p2pkh(network: str):
    value = 0  # mainnet
    if network == 'testnet':
        value = 111
    elif network == 'regtest':
        value = 111
    return value


def get_addr_type_p2sh(network: str):
    value = 5  # mainnet
    if network == 'testnet':
        value = 196
    elif network == 'regtest':
        value = 196
    return value


def get_segwit_hrp(network: str):
    value = "bc"  # mainnet
    if network == 'testnet':
        value = "bc"
    elif network == 'regtest':
        value = "bcrt"
    return value


def ripemd(x: bytes) -> bytes:
    try:
        md = hashlib.new('ripemd160')
        md.update(x)
        return md.digest()
    except BaseException:
        # ripemd160 is not guaranteed to be available in hashlib on all platforms.
        # Historically, our Android builds had hashlib/openssl which did not have it.
        # see https://github.com/spesmilo/electrum/issues/7093
        # We bundle a pure python implementation as fallback that gets used now:
        from . import ripemd
        md = ripemd.new(x)
        return md.digest()


def hash_160(x: bytes) -> bytes:
    return ripemd(sha256(x))


def hash160_to_p2pkh(h160: bytes, network: str) -> str:
    return hash160_to_b58_address(h160, get_addr_type_p2pkh(network))


def hash160_to_p2sh(h160: bytes, network: str) -> str:
    return hash160_to_b58_address(h160, get_addr_type_p2sh(network))


def public_key_to_p2pkh(public_key: bytes, network: str) -> str:
    return hash160_to_p2pkh(hash_160(public_key), network)


def hash_to_segwit_addr(h: bytes, witness_version: int, network: str) -> str:
    addr = encode(get_segwit_hrp(network), witness_version, h)
    assert addr is not None
    return addr


def get_address_from_output_script(_bytes: bytes, network: str) -> Optional[str]:
    try:
        decoded = [x for x in script_get_op(_bytes)]
    except MalformedBitcoinScript:
        return None
    # p2pkh
    if match_script_against_template(decoded, SCRIPT_PUBKEY_TEMPLATE_P2PKH):
        return hash160_to_p2pkh(decoded[2][1], network=network)

    # p2sh
    if match_script_against_template(decoded, SCRIPT_PUBKEY_TEMPLATE_P2SH):
        return hash160_to_p2sh(decoded[1][1], network=network)

    # segwit address (version 0)
    if match_script_against_template(decoded, SCRIPT_PUBKEY_TEMPLATE_WITNESS_V0):
        return hash_to_segwit_addr(decoded[1][1], witness_version=0, network=network)

    # segwit address (version 1-16)
    future_witness_versions = list(range(OpCodes.OP_1, OpCodes.OP_16 + 1))
    for witver, opcode in enumerate(future_witness_versions, start=1):
        match = [opcode, OPPushDataGeneric(lambda x: 2 <= x <= 40)]
        if match_script_against_template(decoded, match):
            return hash_to_segwit_addr(decoded[1][1], witness_version=witver, network=network)

    return None


OP_ANYSEGWIT_VERSION = OPGeneric(lambda x: x in list(range(OpCodes.OP_1, OpCodes.OP_16 + 1)))
SCRIPT_PUBKEY_TEMPLATE_ANYSEGWIT = [OP_ANYSEGWIT_VERSION, OPPushDataGeneric(lambda x: x in list(range(2, 40 + 1)))]
SCRIPT_PUBKEY_TEMPLATE_P2WSH = [OpCodes.OP_0, OPPushDataGeneric(lambda x: x == 32)]
SCRIPT_PUBKEY_TEMPLATE_P2WPKH = [OpCodes.OP_0, OPPushDataGeneric(lambda x: x == 20)]
SCRIPT_PUBKEY_TEMPLATE_P2SH = [OpCodes.OP_HASH160, OPPushDataGeneric(lambda x: x == 20), OpCodes.OP_EQUAL]
SCRIPT_PUBKEY_TEMPLATE_P2PKH = [OpCodes.OP_DUP, OpCodes.OP_HASH160,
                                OPPushDataGeneric(lambda x: x == 20),
                                OpCodes.OP_EQUALVERIFY, OpCodes.OP_CHECKSIG]
SCRIPT_PUBKEY_TEMPLATE_WITNESS_V0 = [OpCodes.OP_0, OPPushDataGeneric(lambda x: x in (20, 32))]
