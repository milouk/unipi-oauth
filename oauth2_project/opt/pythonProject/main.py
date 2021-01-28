# Stream Cipher using One Time Pad (OTP) to encrypt plaintext using OOP technique.
# OTP can be Unicode, Hex, BIN.
import base64
import hashlib
import math
import random
from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import AES

BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


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

class encryption:
    def __init__(self, plainText, otpKey):
        self.key = md5(otpKey.encode('utf8')).hexdigest()
        self.plainText = plainText
        self.otpKey = otpKey

    def charToBinConvertor(self):
        ptToAscii = [ord(letter) for letter in self.plainText]
        ptCharToBin = list()
        for item in ptToAscii:
            ptCharToBin.append(f'{item:08b}')
        # print('Message as bin is: ', messageToBin)
        pt_Char_In_Bin_Format = ''.join(ptCharToBin)
        # print('PT is: ', char_In_Bin_Format)
        # Check otpKey is in binary format or not.
        for i in str(self.otpKey):
            if (i in '10'):
                otpBinState = True
            else:
                otpBinState = False
        if otpBinState == False:
            otp_Char_In_Bin_Format = processOTP(self.otpKey)
        else:
            otp_Char_In_Bin_Format = ''
        return pt_Char_In_Bin_Format, otp_Char_In_Bin_Format

    def OTPencryption(self):
        PT_Bin, OTP_BIN = self.charToBinConvertor()
        if (len(OTP_BIN) == 0):
            # Perform Xor
            xoringPTandKey = int(self.otpKey, 2) ^ int(PT_Bin, 2)
        else:
            xoringPTandKey = int(OTP_BIN, 2) ^ int(PT_Bin, 2)
            # Convert to hex
        encryptedTex = hex(xoringPTandKey)[2:]
        return encryptedTex

    def encryptCBC(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(raw))


def processOTP(otpKey):
    # Check string type before conversion.
    if (otpKey.isalpha() == True):
        # Convert to Alphabet to ASCII.
        otpToAscii = [ord(letter) for letter in otpKey]
        otpCharToBin = list()
        for item in otpToAscii:
            otpCharToBin.append(f'{item:08b}')
        otp_Char_In_Bin_Format = ''.join(otpCharToBin)
    else:
        # Convert Hex to Bin.
        try:
            otp_Char_In_Bin_Format = bin(int(otpKey, base=16))
        except ValueError:
            print('OTP is not in hex.')
    return otp_Char_In_Bin_Format


class decryption:
    def __init__(self, cipherText, otpKey):
        self.key = md5(otpKey.encode('utf8')).hexdigest()
        self.cipherText = cipherText
        self.otpKey = otpKey

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:])).decode('utf8')

    def convertHexToBin(self):
        # Convert hex to bin.
        CTtoBin = bin(int(self.cipherText, base=16))
        # print('CT is: ', CTtoBin[2:])
        return CTtoBin

    def decryptCipher(self):
        CTtoBin = self.convertHexToBin()
        print('Getting original plaintext...')
        for i in str(self.otpKey):
            if (i in '10'):
                binStateOfotpForDecryption = True
            else:
                binStateOfotpForDecryption = False
        if binStateOfotpForDecryption == True:
            deducedMsgAsInt = int(self.otpKey, 2) ^ int(CTtoBin, 2)
            decryptedMsg = self.getDecryptedData(deducedMsgAsInt)
            return decryptedMsg
        else:
            processedOptKey = processOTP(self.otpKey)
            deducedMsgAsInt = int(processedOptKey, 2) ^ int(CTtoBin, 2)
            decryptedMsg = self.getDecryptedData(deducedMsgAsInt)
            return decryptedMsg

    def getDecryptedData(self, deducedMsgAsInt):
        binString = '0' + '{0:b}'.format(deducedMsgAsInt)
        # print('PT is: ', deducedMessageBin)
        binToIntString = int(binString, 2)
        return binToIntString.to_bytes((binToIntString.bit_length() + 7) // 8, 'big').decode()


if __name__ == "__main__":
    OTP = generateOTP()
    # OTP = '110100000111101000010100010101101001111111111010110011100111111011000011101110100110111101011111011000100011'
    PT = "attack to your home"

    print('Initializing...')
    print('Plaintext: ', PT +" and OTP "+ OTP)
    # Instantiate encryption class.
    encrypt = encryption(PT, OTP)
    encryptedText = encrypt.OTPencryption()
    print('Stream Cipher using One Time Pad (OTP) : ', encryptedText)

    aesEncrypt = encrypt.encryptCBC(encryptedText)


    print('Ciphertext AES IN CBC:', aesEncrypt)

    # Instantiate decryption class.
    decrypt = decryption(encryptedText, OTP)
    recoveredText = decrypt.decryptCipher()

    aesDecrypt = decrypt.decrypt(aesEncrypt)
    print('DECRYPT AES IN CBC:', aesDecrypt)

    print('Original text: ', recoveredText)
