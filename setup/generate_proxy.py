"""Generate forwarding declarations from the actual cryptlib public header.

Only signatures and symbol names are generated, not cryptographic code. The
header remains an external build input. No Mystic profile values are included.
"""
import argparse
from pathlib import Path
import re

parser = argparse.ArgumentParser()
parser.add_argument('header', type=Path)
parser.add_argument('output', type=Path)
parser.add_argument('--windows-x86', action='store_true')
args = parser.parse_args()
text = args.header.read_text(errors='strict')
functions = list(re.finditer(r'C_RET\s+(crypt\w+)\s*\(([^;]*?)\)\s*(?:C_ATTRIBUTE_DEPRECATED\s*)?;', text, re.S))
assert len(functions) >= 50, 'Unrecognized cryptlib header'
lines = ['/* Generated API forwarders; no Mystic credentials. */']
exports = ['EXPORTS']
for function in functions:
    name, signature = function.groups()
    if name == 'cryptGetDirectAPI':
        continue  # Optional internal API is not imported by the qualified MIS builds.
    signature = ' '.join(signature.split())
    parameters = [] if signature == 'void' else signature.split(',')
    names = []
    for parameter in parameters:
        match = re.search(r'\b([A-Za-z_]\w*)\s*$', parameter)
        assert match, 'Unsupported API parameter declaration'
        names.append(match[1])
    lines += [f'C_RET {name}({signature}) {{',
              f'    typedef int (PROXY_CALL *Function)({signature});',
              f'    Function target = (Function)proxy_symbol("{name}");',
              '    if (!target) return CRYPT_ERROR_NOTAVAIL;']
    if name == 'cryptGetPrivateKey':
        assert names == ['keyset', 'cryptContext', 'keyIDtype', 'keyID', 'password']
        lines += ['    if (keyIDtype == CRYPT_KEYID_NAME && keyID && password)',
                  '        capture_values(keyID, password);']
    lines += ['    return target(' + ', '.join(names) + ');', '}']
    exported = name
    if args.windows_x86:
        exported += '=_' + name + '@' + str(len(parameters) * 4)
    exports.append('    ' + exported)
args.output.mkdir(parents=True, exist_ok=True)
(args.output / 'proxy_api.inc').write_text('\n'.join(lines) + '\n')
(args.output / 'proxy.def').write_text('\n'.join(exports) + '\n')
print('Generated', len(functions), 'cryptlib API forwarders; no profile data')
