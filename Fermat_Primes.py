#!/usr/bin/python3

import math
import random
import sympy


def isqrt(n):
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def est():
    t0 = 0
    t1 = 0
    t2 = 0
    N = 256

    #  while t0 == 0:
    #       p = 2*random.randint(0, 2 ** N-1)+3
    #       #p = 11
    #      if sympy.isprime(p) == 1:
    #          t0 = 1
    #         k = 4 * (p - 2 ** (N // 2)) * (2 ** (N + 2) - p) + 1
    #         print("2^N = 2^%s, p = %s\n" % (N,p))
    #        #print("" % k)

    p = random.randint(0, 2 ** N - 1)
    k = 4 * p * (2 ** N - p) + 1 #UDI: k = 1 mod 4
    print("2^N = 2^%s, p = %s\n" % (N, p))
    m = 2 ** (N // 2) #UDI: why only half bitlength?

    while t1 == 0:
        a = 2 * random.randint(1, m) #UDI: why even?
        if sympy.isprime(k - a * a) == 1:
            t1 = 1
            # print("K = %s,\nA= %s\n\n" % (k, a))
            q = k - a * a   #UDI: q prime = 1 mod 4 (because choice of a even)
    # print("q = %s,\n\n" % q)
    
    while t2 == 0:
        b = random.randint(0, q)
        if pow(b, (q - 1) // 2, q) == q - 1:
            t2 = 1
            b = pow(b, (q - 1) // 4, q) #UDI: b^2 = -1 mod q (because of choice of q mod 4 = 1)
            # print("b= %s\n\n" % b)

    rz = b
    rm = q
    r0 = b % rm

    while r0 * r0 >= q:
        # print("rz= %s\nrm= %s\nr0= %s\n" % (rz, rm, r0))
        rz = rm
        rm = r0
        r0 = rz % rm
        # print("rz= %s\nrm= %s\nr0= %s\n" % (rz, rm, r0))

    c = sympy.sqrt(q - r0 * r0)
    # print("r0= %s\nc= %s\n" % (r0, c))
    c = rm % r0
    # print("next= %s\n" % c)
    fl = k - a * a - r0 * r0 - c * c
    if fl == 0:
        print("4*p*(2^N - p)+1 = %s =  %s^2   +  %s^2  +  %s^2 \n" % (k, a, r0, c))


est()
