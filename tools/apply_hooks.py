"""Re-apply the env-gated hooks in tools/hooks/ to the generated sources.

src/game/recomp/gen/ is gitignored and regenerated from the PE, so every hook added to it -- and
there are a lot of them -- is lost the moment the generator runs. These hook files carry the ones
that would be expensive to rediscover, anchored to a line of generated code rather than to a line
number, so they survive a regeneration that shifts offsets.

    python -m tools.apply_hooks --check    report status, change nothing (exit 1 if any anchor is gone)
    python -m tools.apply_hooks            apply every hook that is not already applied

A hook file is a small header plus a body:

    # hook:   <name, also the marker written into the source>
    # file:   <basename under src/game/recomp/gen/>
    # mode:   before | after
    # anchor: <one line of generated code, must occur EXACTLY once in the file>
    # --- body ---
    <C, inserted before or after the anchor line>

Applying wraps the body in /* >>> hook: name */ ... /* <<< hook: name */, which is how a second
run recognises it and skips. An anchor that is missing or ambiguous is a hard error: it means the
generated code changed shape and the hook needs re-deriving, which is exactly the thing that
should be loud rather than silently skipped.
"""
import io, os, sys, glob

GEN = os.path.join('src', 'game', 'recomp', 'gen')
HOOKS = os.path.join('tools', 'hooks')


def read(path):
    return io.open(path, encoding='utf-8', errors='surrogateescape').read()


def write(path, text):
    io.open(path, 'w', encoding='utf-8', errors='surrogateescape', newline='').write(text)


def parse_hook(path):
    head, body, in_body = {}, [], False
    for line in read(path).split('\n'):
        if in_body:
            body.append(line)
        elif line.startswith('# --- body ---'):
            in_body = True
        elif line.startswith('# ') and ':' in line:
            k, v = line[2:].split(':', 1)
            head[k.strip()] = v.strip() if k.strip() != 'anchor' else v[1:]
    while body and not body[-1].strip():
        body.pop()
    for k in ('hook', 'file', 'mode', 'anchor'):
        if k not in head:
            raise SystemExit('%s: missing "# %s:"' % (path, k))
    if head['mode'] not in ('before', 'after'):
        raise SystemExit('%s: mode must be before|after' % path)
    return head, body


def main(argv):
    check = '--check' in argv
    paths = sorted(glob.glob(os.path.join(HOOKS, '*.hook')))
    if not paths:
        raise SystemExit('no hooks in %s' % HOOKS)
    missing = applied = added = 0

    for path in paths:
        head, body = parse_hook(path)
        name, target = head['hook'], os.path.join(GEN, head['file'])
        marker = '/* >>> hook: %s */' % name
        if not os.path.exists(target):
            print('  MISSING FILE  %-22s %s' % (name, target))
            missing += 1
            continue
        text = read(target)

        if marker in text:
            print('  applied       %-22s %s' % (name, head['file']))
            applied += 1
            continue

        lines = text.split('\n')
        hits = [i for i, l in enumerate(lines) if l == head['anchor']]
        if len(hits) != 1:
            print('  ANCHOR %-6s %-22s %s  (found %d, need exactly 1)'
                  % ('GONE' if not hits else 'AMBIG', name, head['file'], len(hits)))
            missing += 1
            continue

        # Not marked, but the body may already be there verbatim from a hand edit.
        if body and body[0] in lines:
            print('  applied*      %-22s %s  (present, unmarked)' % (name, head['file']))
            applied += 1
            continue

        if check:
            print('  MISSING       %-22s %s  (anchor ok, would apply)' % (name, head['file']))
            added += 1
            continue

        at = hits[0] + (1 if head['mode'] == 'after' else 0)
        block = [marker] + body + ['/* <<< hook: %s */' % name]
        lines[at:at] = block
        write(target, '\n'.join(lines))
        print('  APPLIED       %-22s %s  (%s anchor, %d lines)'
              % (name, head['file'], head['mode'], len(body)))
        added += 1

    print('\n%d hook(s): %d in place, %d %s, %d unresolved'
          % (len(paths), applied, added, 'to apply' if check else 'applied', missing))
    return 1 if missing else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
