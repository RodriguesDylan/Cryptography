# __ hash_dictionaryAttack.py __
#
# https://github.com/RodriguesDylan/Cryptography/HashCracker/
#
# 2022 Dylan Rodrigues
import hashlib
import sys

def MD5(message):
    x = hashlib.md5(message.encode('utf-8')).hexdigest()
    return x


def SHA1(message):
    x = hashlib.sha1(message.encode('utf-8')).hexdigest()
    return x


def SHA256(message):
    x = hashlib.sha256(message.encode('utf-8')).hexdigest()
    return x


def SHA512(message):
    x = hashlib.sha512(message.encode('utf-8')).hexdigest()
    return x


def SHA3_224(message):
    x = hashlib.sha3_224(message.encode('utf-8')).hexdigest()
    return x


def SHA3_256(message):
    x = hashlib.sha3_256(message.encode('utf-8')).hexdigest()
    return x


def SHA3_384(message):
    x = hashlib.sha3_384(message.encode('utf-8')).hexdigest()
    return x


def SHA3_512(message):
    x = hashlib.sha3_512(message.encode('utf-8')).hexdigest()
    return x


def BLAKE2s(message):
    x = hashlib.blake2s(message.encode('utf-8')).hexdigest()
    return x


def BLAKE2b(message):
    x = hashlib.blake2b(message.encode('utf-8')).hexdigest()
    return x


def SHA3_process():
    chosenFunction = getNumeric(
        "Choose a SHA3 :\n1.SHA3_224   2.SHA3_256   3.SHA3_384   4.SHA3_512\n")
    optionsSHA3 = {1: SHA3_224,
                   2: SHA3_256,
                   3: SHA3_384,
                   4: SHA3_512,
                   }
    return optionsSHA3[chosenFunction]


def getNumeric(prompt):
    while True:
        try:
            res = int(input(prompt))
            break
        except ValueError:
            print("Numbers only please!")
    return res


if __name__ == "__main__":
    print("HashBruteforcer V0.1\n")
    while True:
        try:
            file = open(sys.argv[1], 'r', encoding='utf-8')
            break
        except IndexError:
            print("Requiring a password list in txt format as argument!")
            exit()

    hashedMessage = input("Enter/paste hash :\n")  # hash to decode
    chosenNumber = getNumeric(
        "Choose bruteforce algorithm (number) : \n1.MD5   2.SHA-1   3.SHA256   4.SHA512\n5.SHA3   6.BLAKE2s   7.BLAKE2b\n")

    options = {1: MD5,  # available functions
               2: SHA1,
               3: SHA256,
               4: SHA512,
               5: "SHA3go",
               6: BLAKE2s,
               7: BLAKE2b,
               }

    fct = options[chosenNumber]  # chosen hash function
    if (fct == "SHA3go"):
        fct = SHA3_process()
    state = False
    for line in file:
        line = line.strip('\n')
        if (fct(line) == hashedMessage):
            print(f"Found! It's {line}.\n")
            state = True
            break
        else:
            continue

    if (state == False):
        print("Found nothing...\n")

    file.close()
