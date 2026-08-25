"""A small local list of passwords that appear at the top of every public
credential dump, used for offline weak-password detection.

This is *not* a breach database. Membership here means "this is a famously
common password", not "this credential was exposed". Real breach lookups are a
separate, optional, local-dataset feature -- see core/breach.py.
"""

from __future__ import annotations

_RAW = """
123456 password 123456789 12345678 12345 1234567 qwerty abc123 111111 123123
1234567890 1234 iloveyou 000000 admin welcome monkey login dragon passw0rd
master hello freedom whatever qazwsx trustno1 letmein sunshine princess
football baseball starwars shadow michael superman batman jordan harley
ranger hunter buster soccer hockey killer george charlie andrew michelle
love jessica asshole pepper daniel access joshua maggie 654321 pussy
mustang 696969 jennifer 2000 test qwertyuiop asdfgh zxcvbn 1q2w3e4r
1qaz2wsx qwerty123 password1 password123 admin123 root toor guest user
default changeme secret pass letmein123 abcd1234 a1b2c3 aaaaaa 121212
112233 abc12345 987654321 asdfghjkl zaq12wsx qwe123 samsung google
facebook twitter internet computer server oracle cisco linux windows
summer winter spring autumn january february march april may june july
august september october november december monday friday sunday
chocolate cookie flower diamond silver golden purple yellow orange
matrix ninja hacker gamer player minecraft pokemon fortnite roblox
lovely angel bailey ashley amanda nicole hannah taylor jasmine
tigger thomas robert richard william joseph david john james
qwertz azerty 147258369 159753 123321 555555 666666 777777 888888
999999 101010 202020 123abc abc abcdef qazxsw trustme welcome1
p@ssw0rd p@ssword passw0rd1 admin1 administrator manager operator
backup temp temp123 test123 demo sample example dummy
"""

COMMON_PASSWORDS = frozenset(w for w in _RAW.split() if w)


def is_common(password: str) -> bool:
    p = (password or "").strip().lower()
    if not p:
        return False
    if p in COMMON_PASSWORDS:
        return True
    # Strip a trailing year/number run and a trailing punctuation mark, which is
    # the overwhelmingly common way people "strengthen" a weak base password.
    stripped = p.rstrip("!@#$%^&*.")
    core = stripped.rstrip("0123456789")
    return bool(core) and core in COMMON_PASSWORDS and len(stripped) - len(core) <= 4
