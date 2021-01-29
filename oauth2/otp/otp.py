# Stream Cipher using One Time Pad (OTP) to encrypt plaintext using OOP technique.
# OTP can be Unicode, Hex, BIN.
import math
import random


def generateOTP():
    # Declare a digits variable
    # which stores all digits
    digits = "0123456789"
    OTP = ""
    # length of password can be chaged
    # by changing value in range
    for i in range(4):
        OTP += digits[math.floor(random.random() * 10)]
    return OTP
