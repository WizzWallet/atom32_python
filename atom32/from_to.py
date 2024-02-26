from atom32.address_script import detect_address_type_to_script_hash, get_address_from_output_script
from atom32.conversion import convert_bits, bech32_encode, bech32_decode


def to_atom_32(address: str, network: str, use_hrp: str = 'atom', spec: int = 1):
    result = detect_address_type_to_script_hash(address, network)
    output = result['output']
    to_width = 5
    bz = convert_bits(output, 8, to_width)
    if bz is None:
        raise Exception(f'Could not convert byte Buffer to {to_width}-bit Buffer')
    return bech32_encode(use_hrp, bz, spec)


def from_atom32(address: str, network: str, use_hrp: str = 'atom'):
    res = bech32_decode(address)
    if res is None:
        raise ValueError('Invalid bech32 address')
    hrp, data = res
    if hrp != use_hrp:
        raise ValueError(f'Expected hrp to be {use_hrp} but got {hrp}.')
    buf = convert_bits(data, 5, 8, False)
    if buf is None:
        raise ValueError('Could not convert buffer to bytes')
    return get_address_from_output_script(buf, network)
