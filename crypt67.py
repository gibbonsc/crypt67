import math,sys

# encrypt67 function machinery: numeral bigram bijections
op1 = lambda j,k: (
    (43, 29, 37, 33, 46, 39, 36),
    (45, 38, 44, 25, 42, 48,  0),
    ( 9, 14,  3, 15, 13, 16, 21),
    (20,  1,  2, 12,  5, 26, 27),
    ( 4, 28,  6, 30,  7, 31,  8),
    (32, 10, 34, 11, 35, 40, 17),
    (41, 18, 19, 22, 23, 47, 24)
)[j][k]  # semivoluntarily incomputable
op2 = lambda j,k: (
    ( 4,  1, 14,  7,  5, 18, 15),
    (21, 19, 12, 24,  0, 28, 39),
    (45, 26, 36, 29, 44, 42, 25),
    (27, 35, 33, 38, 31,  2,  3),
    ( 6, 30,  8, 32,  9, 10, 34),
    (11, 13, 37, 16, 40, 17, 41),
    (43, 20, 22, 46, 23, 47, 48)
)[j][k]  # dangerously doubletracking
op3 = lambda j,k: (
    (43,  8,  0,  1, 26,  3, 14),
    ( 5, 29, 20, 10,  7, 45,  9),
    (44, 22, 31, 11, 38, 13, 33),
    (36, 16, 15, 42, 18, 47, 35),
    (28, 17, 40, 19, 24, 37,  2),
    (39, 32, 21,  4, 48, 34, 23),
    (12, 25, 41, 46,  6, 27, 30)
)[j][k]  # prime indices (almost)

# decrypt67 inverse functions
op1i = lambda j,k: (
    (13, 22, 23, 16, 28, 25, 30),
    (32, 34, 14, 36, 38, 24, 18),
    (15, 17, 19, 41, 43, 44, 21),
    (20, 45, 46, 48, 10, 26, 27),
    (29,  1, 31, 33, 35,  3, 37),
    (39,  6,  2,  8,  5, 40, 42),
    (11,  0,  9,  7,  4, 47, 12)
)[j][k]
op2i = lambda j,k: (
    (11,  1, 26, 27,  0,  4, 28),
    ( 3, 30, 32, 33, 35,  9, 36),
    ( 2,  6, 38, 40,  5,  8, 43),
    ( 7, 44, 46, 10, 20, 15, 21),
    (12, 17, 29, 25, 31, 23, 34),
    (22, 16, 37, 24, 13, 39, 41),
    (19, 42, 18, 14, 45, 47, 48)
)[j][k]
op3i = lambda j,k: (
    ( 2,  3, 34,  5, 38,  7, 46),
    (11,  1, 13, 10, 17, 42, 19),
    ( 6, 23, 22, 29, 25, 31,  9),
    (37, 15, 41, 32, 43,  4, 47),
    (28,  8, 48, 16, 36, 20, 40),
    (27, 21, 33, 18, 35, 30, 44),
    (24,  0, 14, 12, 45, 26, 39)
)[j][k]

def encrypt67(plaintext: bytes) -> bytes:
    """
    convert plaintext to ciphertext using encrypt67 algorithm

    :param plaintext: bytes instance containing message to encrypt
    :return: bytes instance containing encrypted message
    """
    if not isinstance(plaintext, bytes):
        raise TypeError(f"Expected argument of type bytes, got {type(plaintext).__name__}")

    s = int.from_bytes(plaintext)  # convert bytes to int
    ss = s  # state register; process plaintext number until 0
    cc = 0  # state register; processed ciphertext number

    while ss > 0:
        d=[]
        block = ss % 117649   # six septenary plaintext digits
        for n in range(6):
            d.insert(0,block%7)  # isolate septenary digit
            block //= 7
        # most significant digit is in d[0], least in d[5]

        ir1 = op1(d[4],d[5])  # invoke encrypt67 processes
        ir2 = op2(d[2],d[3])
        ir3 = op3(d[0],d[1])
        e=(ir3//7, ir3%7, ir2//7, ir2%7, ir1//7, ir1%7)  # encrypted septenary digits
        # most significant digit is in e[0], least in e[5]

        cc *= 117649  # shift previous ciphertext accumulations
        cc += ir3*2401 + ir2*49 + ir1  # accumulate six septenary ciphertext digits

        ss //= 117649  # unshift processed plaintext digits

    # convert accumulated ciphertext to bytes
    ct = cc.to_bytes(math.ceil(math.log(cc,256)), byteorder='big')
    return ct

def decrypt67(ciphertext):
    """
    convert ciphertext that was encrypted with encrypt67 algorithm back to plaintext

    :param ciphertext: bytes to decrypt
    :return: bytes containing decrypted message
    """
    if not isinstance(ciphertext, bytes):
        raise TypeError(f"Expected argument of type bytes, got {type(ciphertext).__name__}")


    c = int.from_bytes(ciphertext)  # convert bytes to int
    cc = c  # state registers; process ciphertext number until 0
    pp = 0  # state register; processed plaintext number

    while cc > 0:
        e=[]
        block = cc % 117649  # six septenary ciphertext digits
        for n in range(6):
            e.insert(0,block%7)  # isolate septenary digit
            block //= 7

        ir1 = op1i(e[4],e[5])  # invoke decrypt67 processes
        ir2 = op2i(e[2],e[3])
        ir3 = op3i(e[0],e[1])
        d=(ir3//7, ir3%7, ir2//7, ir2%7, ir1//7, ir1%7)  # decrypted septenary digits

        pp *= 117649  # shift preceeding plaintext accumulations
        pp += ir3*2401 + ir2*49 + ir1  # accumulate six plaintext digits
        cc //= 117649  # unshift processed ciphertext diits

    # convert accumulated plaintext to bytes
    pt = pp.to_bytes(math.ceil(math.log(pp,256)), byteorder='big')
    return pt

def main():
    plaint=input("Enter plain text: ").encode()
    print(f"########## PLAINTEXT:\n{plaint}\n")

    ciphert = encrypt67(plaint)
    print(f"########## CIPHERTEXT:\n{ciphert}\n")
    try:
        open("crypt67.out","wb").write(ciphert)
    except:
        print("Error: couldn't save ciphertext to crypt67.out")

    recover = decrypt67(ciphert)
    print(f"########## RECOVERED:\n{recover}\n")
    try:
        open("crypt67.txt","wt").write(recover.decode())
    except:
        print("Error: couldn't save recovered text to crypt67.txt")

if __name__=="__main__":
    main()
