"""Fix TEST codegen bug: CMP_GE(x, x) -> TEST_NS(x, x) etc."""
import re
import sys

replacements = {
    'CMP_GE': 'TEST_NS',
    'CMP_G': 'TEST_G',
    'CMP_LE': 'TEST_LE',
}

def fix_test_cond(m):
    macro = m.group(1)
    reg = m.group(2)
    new_macro = replacements.get(macro, macro)
    if new_macro != macro:
        return f'{new_macro}({reg}, {reg})'
    return m.group(0)

pattern = r'(CMP_GE|CMP_G|CMP_LE)\(([^,)]+), \2\)'

for filepath in sys.argv[1:]:
    with open(filepath, 'r') as f:
        content = f.read()

    new_content, count = re.subn(pattern, fix_test_cond, content)

    if count > 0:
        with open(filepath, 'w') as f:
            f.write(new_content)
        print(f'{filepath}: {count} fixes')
    else:
        print(f'{filepath}: no fixes needed')
