import hashlib


def check(value, correct_hash):
    m = hashlib.md5()
    m.update(value.encode())
    test_hash = m.digest()
    if correct_hash == test_hash:
        return "Correct!"
    else:
        return "Incorrect"


def test_percent_synonly(percent_synonly):
    correct_hash = b'*8\xa4\xa91lI\xe5\xa83Q|E\xd3\x10p'
    test_percentage = str(round(percent_synonly))
    return check(test_percentage, correct_hash)


def test_percent_knownbad(percent_knownbad):
    correct_hash = b'\x16y\t\x1cZ\x88\x0f\xafo\xb5\xe6\x08~\xb1\xb2\xdc'
    test_percentage = str(round(percent_knownbad))
    return check(test_percentage, correct_hash)


def test_percent_synonly_knownbad(percent_synonly_knownbad):
    correct_hash = b'\xf8\x99\x13\x9d\xf5\xe1\x05\x93\x96C\x14\x15\xe7p\xc6\xdd'
    test_percentage = str(round(percent_synonly_knownbad))
    return check(test_percentage, correct_hash)


def test_percent_synonly_NOTknownbad(percent_synonly_other):
    correct_hash = b'*8\xa4\xa91lI\xe5\xa83Q|E\xd3\x10p'
    test_percentage = str(round(percent_synonly_other))
    return check(test_percentage, correct_hash)


def test_num_malicious_hosts(num_malicious_hosts):
    correct_hash = b'\xc8\x9c\xa3nM\x040\xe7\\\xa29\x04p\xa5\x9aY'
    test_num = str(num_malicious_hosts)
    return check(test_num, correct_hash)


def test_num_benign_hosts(num_benign_hosts):
    correct_hash = b'2\x95\xc7j\xcb\xf4\xca\xae\xd3<6\xb1\xb5\xfc,\xb1'
    test_num = str(num_benign_hosts)
    return check(test_num, correct_hash)
          

def test_num_questionable_hosts(num_questionable_hosts):
    correct_hash = b"\xc2\n\xd4\xd7o\xe9wY\xaa'\xa0\xc9\x9b\xffg\x10"
    test_num = str(num_questionable_hosts)
    return check(test_num, correct_hash)


def test_num_blocked_hosts(num_blocked_hosts):
    correct_hash = b'\x98\xfe\x9e}\x88D\xd3\xe2\x98\x0c\xd0w\x8b\xaav-'
    test_val = str(num_blocked_hosts)
    return check(test_val, correct_hash)