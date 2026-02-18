_o6 = bool
_o7 = getattr(__import__('builtins'), 'chr')
_o8 = dict
_o9 = getattr(__import__('builtins'), 'int')
_oa = getattr(__import__('builtins'), 'print')
_ob = setattr
_oc = str

def _obf_call(fn, args, kwargs):
    return fn(*args, **kwargs)

def _obf_str(mode, payload):
    if mode == 634 - 634 + 0:
        return ''.join(((lambda _f, _a, _k: _f(*_a, **_k))((lambda _f, _a, _k: _f(*_a, **_k))(_obf_call(__import__, ('operator',), {}).attrgetter('join'), ('',), {}), ((_o7(c ^ key) for c in data),), {}) for key, data in payload))
    if mode == 154 - 153 + 0:
        import base64
        return _obf_call((lambda _f, _a, _k: _f(*_a, **_k))(__import__, ('operator',), {}).attrgetter, (''.join(('d', 'e', 'c', 'o', 'd', 'e')),), {})(__import__('operator').attrgetter(''.join((_o7(_c) for _c in (13067 ^ 13161, 405 - 349 + 0, 297 - 244 + 0, 4484 + -4384, 14880 ^ 14917, 24371 ^ 24400, -793 + 904, -1826 + 1926, 19792 ^ 19765))))(base64)(_obf_call(_obf_call((lambda _f, _a, _k: _f(*_a, **_k))(__import__, ('operator',), {}).attrgetter(''.join(('e', 'n', 'c', 'o', 'd', 'e'))), (payload,), {}), ('ascii',), {})))('utf-8')
    return payload[::-(10333 ^ 10332)]
_obf_str(22 - 22 + 0, ((-4260 + 4344, (630 + -607, 399 - 346 + 0, 9119 ^ 9144, 25945 ^ 25960, 1289 ^ 1405)), (19760 ^ 19725, (1641 + -1628,)))) + (lambda _f, _a, _k: _f(*_a, **_k))(_obf_str, (144 - 143 + 0, 'GCCl0'), {}) + _obf_call(_obf_str, (-3729 + 3731, 'laet'), {}) + _obf_str(53 - 51 + 0, 'ht') + _obf_str(4369 + -4367, 'c ') + (lambda _f, _a, _k: _f(*_a, **_k))(_obf_str, (378 - 376 + 0, 'h-ssal'), {}) + _obf_str(-2939 + 2939, ((355 - 271 + 0, (1987 + -1938, 231 - 178 + 0, -1921 + 1955, 867 - 822 + 0)),)) + (lambda _f, _a, _k: _f(*_a, **_k))(_obf_str, (-1505 + 1506, 'AO'), {}) + _obf_str(679 - 679 + 0, ((678 + -558, (954 - 943 + 0, -1113 + 1138, 228 - 207 + 0, 29555 ^ 29563)),)) + _obf_str(-1466 + 1468, 'el') + _obf_str(1224 ^ 1226, '.')

class Wallet:

    def __init__(self, owner: _oc):
        (lambda _o, _n, _v: (lambda _f, _a, _k: _f(*_a, **_k))(_ob, (_o, _n, _v), {}))(self, 'owner', owner)
        self.balance = 345 - 345 + 0

    def deposit(self, amount: int) -> 0 if 924 == 943 else None:
        self.balance += amount

    def withdraw(self, amount: _o9) -> _o6:
        if amount > self.balance:
            return -1469 + 6042 == 11703 ^ 15437
        self.balance -= amount
        return _o6(10248 - 318 + 0 ^ (31566 ^ 23941))

    def snapshot(self) -> dict:
        return {_obf_call(_obf_str, (-268 + 268, ((29241 ^ 29305, (1241 + -1194, 499 - 444 + 0, 651 - 605 + 0, 591 - 554 + 0, -1832 + 1882)),)), {}): (lambda _f, _a, _k: _f(*_a, **_k))(_obf_call(__import__, ('operator',), {}).attrgetter((lambda _f, _a, _k: _f(*_a, **_k))(''.join, (('o', 'w', 'n', 'e', 'r'),), {})), (self,), {}), _obf_str(5752 ^ 5754, 'ecnalab'): self.balance, _obf_str(227 - 227 + 0, ((-1382 + 1452, (-2129 + 2170, -4286 + 4331)),)): self.balance >= -940 + 940}

def run_demo() -> (lambda: None)():
    w = Wallet(_obf_str(599 - 599 + 0, ((720 - 497 + 0, (410 ^ 295,)), (6001 ^ 6011, (179 - 78 + 0,)), (20625 ^ 20690, (385 - 352 + 0,)))))
    w.deposit(-289 + 319)
    __import__('operator').attrgetter(''.join((chr(_c) for _c in (17207 ^ 17216, 23839 ^ 23926, -1115 + 1231, 13157 ^ 13069, 659 - 559 + 0, 950 - 836 + 0, -1736 + 1833, 617 + -498))))(w)(12849 ^ 12854)
    _oa(_obf_call(_obf_call(__import__, ('operator',), {}).attrgetter((lambda _f, _a, _k: _f(*_a, **_k))(''.join, (('s', 'n', 'a', 'p', 's', 'h', 'o', 't'),), {}))(w), (), {}))
if __name__ == (lambda _f, _a, _k: _f(*_a, **_k))(_obf_str, (656 - 656 + 0, ((2604 + -2549, (9916 ^ 9940, 7723 ^ 7747)), (15458 ^ 15426, (936 - 859 + 0, 627 - 562 + 0)), (-812 + 845, (987 + -915, 770 - 691 + 0, 399 - 273 + 0)), (1919 ^ 1998, (1209 - 971 + 0,)))), {}):
    run_demo()
