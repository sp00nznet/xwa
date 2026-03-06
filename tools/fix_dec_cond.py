"""Fix DEC codegen bug: after 'dec X', conditions compare against 1 instead of 0.

x86 DEC sets flags based on the RESULT (post-decrement value).
- dec X; je  -> jump if result == 0, NOT if result == 1
- dec X; jne -> jump if result != 0, NOT if result != 1
- dec X; js  -> jump if result < 0,  NOT if result < 1
- dec X; jns -> jump if result >= 0, NOT if result >= 1

The codegen was emitting CMP_XX(X, 1) instead of CMP_XX(X, 0).
"""
import re
import sys

# Pattern: /* dec result */ CMP_XX(something, 1)
pattern = re.compile(
    r'(/\* dec result \*/ )(CMP_(?:EQ|NE|S|NS))\(([^,]+), 1\)'
)

def fix_dec_cond(m):
    comment = m.group(1)
    macro = m.group(2)
    operand = m.group(3)
    return f'{comment}{macro}({operand}, 0)'

for filepath in sys.argv[1:]:
    with open(filepath, 'r') as f:
        content = f.read()

    new_content, count = pattern.subn(fix_dec_cond, content)

    if count > 0:
        with open(filepath, 'w') as f:
            f.write(new_content)
        print(f'{filepath}: {count} fixes')
    else:
        print(f'{filepath}: no fixes needed')
