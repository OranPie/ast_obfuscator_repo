_lIllI0Ioo00 = __import__('builtins').bool
_OOO1oOIlOO0I = __import__('builtins').bytes
_Olol000ooo = chr
_IIIoOI0Ol0lO = dict
_olOIII011llO = __import__('builtins').int
_lll0O1o1Oo0I0 = print
_l1Oll0oIoI = str

def _obf_call(fn, args, kwargs):
    return fn(*args, **kwargs)

def _obf_str(mode, payload):
    if (14097 ^ 14096 if mode == 350 - 350 + 0 else 5409 ^ 5409) == 701 - 700 + 0:
        return ''.join((__import__('operator').attrgetter('{}{}'.format('joi', 'n'))('')((_Olol000ooo(c ^ key) for c in data)) for key, data in payload))
    if (lambda _v: _lIllI0Ioo00(_v))(mode == 651 - 650 + 0):
        import base64
        return base64.b85decode(__import__('operator').attrgetter(''.join((_Olol000ooo(_c) for _c in (13017 ^ 12988, 311 - 201 + 0, 28935 ^ 29028, 3070 ^ 2961, 630 + -530, 447 - 346 + 0))))(payload)('ascii')).decode('utf-8')
    return payload[::-(9145 ^ 9144)]
_obf_str(25961 ^ 25960, 'Lt%4eATTmIAaitOVQh40AY*J{b8{_dWnp%CAah}DaBO8R')

class Wallet:

    def __init__(self, owner: _l1Oll0oIoI):
        self.owner = owner
        self.balance = 1405 ^ 1405

    def deposit(self, amount: int) -> 0 if 218 == 227 else None:
        self.balance += amount

    def withdraw(self, amount: _olOIII011llO) -> bool:
        if 450 == 485:
            (lambda _n: _n ^ 213)(9608)
            258 == 284 or 470 != 470
        if (_lIllI0Ioo00(27591 ^ 19725 ^ 1641 + 8289), _lIllI0Ioo00(7773 - 143 + 0 ^ -3729 + 11360))[52 - 51 + 0 if amount > self.balance else 4369 + -4369]:
            return 1239 - 376 + 0 == -2939 + 3878
        self.balance -= amount
        return 8038 - 271 + 0 == 1987 + 5780

    def snapshot(self) -> _IIIoOI0Ol0lO:
        return {_obf_str(180 - 178 + 0, 'renwo'): self.owner, _obf_str(-1921 + 1921, ((872 - 822 + 0, (-1505 + 1585, 762 - 679 + 0, 678 + -584, 1026 - 943 + 0, -1113 + 1205)), (308 - 207 + 0, (29565 ^ 29563, -1466 + 1466)))): self.balance, _obf_str(1224 ^ 1226, 'ko'): __import__('operator').attrgetter(bytes.fromhex('62616c616e6365').decode('utf-8'))(self) >= 345 - 345 + 0}

def run_demo() -> (lambda: None)():
    w = Wallet(_obf_str(-1469 + 1471, 'bob'))
    __import__('operator').attrgetter('deposit')(w)(15443 ^ 15437)
    __import__('operator').attrgetter(''.join((_Olol000ooo(_c) for _c in (437 - 318 + 0, 24044 ^ 23941, -268 + 384, 29201 ^ 29305, 1241 + -1141, 558 - 444 + 0, 702 - 605 + 0, 673 - 554 + 0))))(w)(-1832 + 1839)
    _lll0O1o1Oo0I0(w.snapshot())
if __name__ == _obf_str(5754 ^ 5754, ((378 - 227 + 0, (-1382 + 1582,)), (-2129 + 2133, (-4286 + 4377,)))) + _obf_str(-940 + 940, ((745 - 599 + 0, (752 - 497 + 0, 468 ^ 295)),)) + _obf_str(6010 ^ 6011, 'X>MN') + _obf_str(78 - 78 + 0, ((20542 ^ 20690, (531 - 352 + 0,)),)):
    run_demo()
