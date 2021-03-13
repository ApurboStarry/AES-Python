# 1. Input the key.
#   perform input calibration.
#   -> If the length of the key is more than 16 characters, discard rest of them
#   -> if the length is less than 16 characters, pad it with '0' to make 16 characters

# 2. Input the text to be encrypted
#   -> You have to divide the input plain text into blocks of '16 characters' and
#   "encrypt one block at a time."

#   -> Pad the input string with "spaces" if its length is not multiple of 16.

# 3. Key Expansion Algorithm


from BitVector import *
import time

def formatKey(key):
    if len(key) > 16:
        key = key[0:16]
    elif len(key) < 16:
        short = 16 - len(key)
        i = 0
        while i < short:
            key += '0'
            i += 1

    return key


def formatPlainText(plainText):
    if len(plainText) % 16 != 0:
        short = 16 * (len(plainText) // 16 + 1) - len(plainText)
        i = 0
        while i < short:
            plainText += ' '
            i += 1
    
    return plainText
    
    
def shiftLeft(l):
    poppedItem = l[0]
    l.pop(0)
    l.append(poppedItem)
    return l
    
def bitVectorToHex(bv):
    return hex(int(str(bv), 2))
    
    
Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)


roundConstants = []
def generateRoundConstants():
    roundConstants.append(0x00)
    roundConstants.append(0x01)
    for i in range(2, 15):
        if roundConstants[i-1] < 0x80:
            roundConstants.append(2 * roundConstants[i-1])
        else:
            roundConstants.append(2 * roundConstants[i-1] ^ 0x11b)


def g(w, roundNumber):
    w3 = []
    for i in w:
        w3.append(i)
    # shift left by 1
    w3 = shiftLeft(w3)
    # byte substitution
    for i in range(0, 4):
        w3[i] = hex(Sbox[int(w3[i], 16)])
        
    # print(w3)
    
    # add round constant
    w3[0] = hex(roundConstants[roundNumber] ^ int(w3[0], 16))
    
    return w3
    
    
def nextRoundKey(w, roundNumber):
    w0 = w[0:4]
    w1 = w[4:8]
    w2 = w[8:12]
    w3 = w[12:16]
    
    # print("w0: ", w0)
    # print("w1: ", w1)
    # print("w2: ", w2)
    # print("w3: ", w3)
    
    gw3 = g(w3[:], roundNumber)
    # print("Modified: ", w3)
    
    w4 = []
    for i in range(0, 4):
        w4.append(hex(int(w0[i], 16) ^ int(gw3[i], 16)))
        
    w5 = []
    for i in range(0, 4):
        w5.append(hex(int(w4[i], 16) ^ int(w1[i], 16)))
    
    w6 = []
    for i in range(0, 4):
        w6.append(hex(int(w5[i], 16) ^ int(w2[i], 16)))
        
    w7 = []
    for i in range(0, 4):
        w7.append(hex(int(w6[i], 16) ^ int(w3[i], 16)))
    
    # print("w4: ", w4)
    # print("w5: ", w5)
    # print("w6: ", w6)
    # print("w7: ", w7)
    
    wPrime = []
    wPrime.append(w4)
    wPrime.append(w5)
    wPrime.append(w6)
    wPrime.append(w7)
    
    return wPrime
        
        
def generateBitVectorFromKey(key):
    w = []
    for i in range(0, len(key)):
        bv = BitVector(textstring=key[i])
        # print(hex(int(str(bv), 2)))
        # print(bitVectorToHex(bv))
        w.append(bitVectorToHex(bv))
    
    return w
    
    
def generateFirstRoundKey(key):
    roundKey = []
    for i in range(4):
     roundKey.append([])
     for j in range(4):
         roundKey[i].append(" ")
    
    index = 0
    for j in range(4):
        for i in range(4):
            roundKey[i][j] = hex(ord(key[index]))
            index += 1
            
    return roundKey
    
    
def addRoundKey(stateMatrix, roundKey):
    newStateMatrix = []
    for i in range(4):
        newStateMatrix.append([])
        
    for i in range(4):
        for j in range(4):
            newStateMatrix[i].append(hex(int(stateMatrix[i][j], 16) ^ int(roundKey[i][j], 16)))
    
    # print("newStateMatrix")
    # for i in range(4):
    #     print(newStateMatrix[i])

    return newStateMatrix
    
    
def substituteBytes(stateMatrix):
    for i in range(4):
        for j in range(4):
            stateMatrix[i][j] = hex(Sbox[int(stateMatrix[i][j], 16)])
            
    # for i in range(4):
    #     print(stateMatrix[i])
    return stateMatrix
    

def shiftRow(stateMatrix):
    for i in range(4):
        for j in range(i):
            popedItem = stateMatrix[i][0]
            # print(i, popedItem)
            stateMatrix[i].pop(0)
            stateMatrix[i].append(popedItem)
            
    # for i in range(4):
    #     print(stateMatrix[i])
        
    return stateMatrix


def mixColumn(stateMatrix):
    newStateMatrix = []
    for i in range(4):
     newStateMatrix.append([])
     for j in range(4):
         newStateMatrix[i].append(" ")
    
    fixedMatrix = []
    fixedMatrix.append([2, 3, 1, 1])
    fixedMatrix.append([1, 2, 3, 1])
    fixedMatrix.append([1, 1, 2, 3])
    fixedMatrix.append([3, 1, 1, 2])
    
    # print("newStateMatrix:", newStateMatrix)
    
    AES_modulus = BitVector(bitstring='100011011')
    
    for j in range(4):
        for rowOfFixedMatrix in range(4):
            xoredValue = 0
            for colOfFixedMatrix in range(4):
                bv1 = BitVector(intVal=fixedMatrix[rowOfFixedMatrix][colOfFixedMatrix])
                bv2 = BitVector(hexstring=stateMatrix[colOfFixedMatrix][j][2:])
                # print(fixedMatrix[rowOfFixedMatrix][colOfFixedMatrix], stateMatrix[colOfFixedMatrix][j])
                bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
                
                xoredValue = xoredValue ^ int(bv3)
                # print("xoredValue", hex(xoredValue))  
                
            newStateMatrix[rowOfFixedMatrix][j] = hex(xoredValue)
                
    # print("newStateMatrix:")
    # for i in range(4):
    #     print(newStateMatrix[i])
         
    return newStateMatrix


def xorList(l1, l2):
    output = []
    for i in range(4):
        output.append(hex(int(l1[i], 16) ^ int(l2[i], 16)))
        
    return output


def generateRoundKey(roundNumber, roundKey):
    newRoundKey = []
    for i in range(4):
        newRoundKey.append([])
        for j in range(4):
             newRoundKey[i].append(" ")

    w0 = [sub[0] for sub in roundKey]
    w1 = [sub[1] for sub in roundKey]
    w2 = [sub[2] for sub in roundKey]
    w3 = [sub[3] for sub in roundKey]
    
    gW3 = g(w3, roundNumber)
    
    w4 = xorList(w0, gW3)
    w5 = xorList(w4, w1)
    w6 = xorList(w5, w2)
    w7 = xorList(w6, w3)
    
    for i in range(4):
        newRoundKey[i][0] = w4[i]
    for i in range(4):
        newRoundKey[i][1] = w5[i]
    for i in range(4):
        newRoundKey[i][2] = w6[i]
    for i in range(4):
        newRoundKey[i][3] = w7[i]

    # for i in range(4):
    #     print(newRoundKey[i])
    return newRoundKey



roundKeys = []

def generateAllTheRoundKeys(key, numberOfRounds):
    roundKey = generateFirstRoundKey(key)
    roundKeys.append(roundKey)

    for i in range(1, numberOfRounds + 1):
        roundKey = generateRoundKey(i, roundKey)
        roundKeys.append(roundKey)
      
    print("number of round keys: ", len(roundKeys))
    # print("All the roundKeys:")
    # for i in range(len(roundKeys)):
    #     for j in range(4):
    #         print(roundKeys[i][j])
    #     print()


def encryptBlock(stateMatrix, numberOfRounds):
    roundKey = roundKeys[0]
    
    # Round 0
    stateMatrix = addRoundKey(stateMatrix, roundKey)
    
    # Round 1 to (numberOfRounds - 1)
    for i in range(1, numberOfRounds):
        stateMatrix = substituteBytes(stateMatrix)
        stateMatrix = shiftRow(stateMatrix)
        stateMatrix = mixColumn(stateMatrix)
        roundKey = roundKeys[i]
        stateMatrix = addRoundKey(stateMatrix, roundKey)
        
    stateMatrix = substituteBytes(stateMatrix)
    stateMatrix = shiftRow(stateMatrix)
    roundKey = roundKeys[numberOfRounds]
    stateMatrix = addRoundKey(stateMatrix, roundKey)
        
    cipher = ""
    for j in range(4):
        for i in range(4):
            cipher += '{0:02x}'.format(int(stateMatrix[i][j], 16))
    
    # print(cipher)
    return cipher


def makeBlock(text):
    block = []
    for i in range(4):
     block.append([])
     for j in range(4):
         block[i].append(" ")
    
    index = 0
    for j in range(0, 4):
        for i in range(0, 4):
            # print(text[index], hex(ord(text[index])))
            block[i][j] = hex(ord(text[index]))
            # print(block[i][j])
            index += 1
        
    # print("unit block: ")
    # for row in block:
    #     print(row)

    return block


def getBlocksOfPlainText(plainText):
    plainText = formatPlainText(plainText)
    blocks = []
    
    numberOfBlocks = len(plainText) // 16
    # print(numberOfBlocks)
    for i in range(0, numberOfBlocks):
        blocks.append(makeBlock(plainText[i*16 : (i+1)*16]))
        
    return blocks


def encrypt(key, plainText, numberOfRounds):    
    generateRoundConstants()
    # print("Round Constants: ", roundConstants)
    
    startTime = time.time()
    generateAllTheRoundKeys(key, numberOfRounds)
    print("\nKey Scheduling Time: " + str(time.time() - startTime) + " seconds\n")
    
    startTime = time.time()
    cipherText = ""
    plainTextBlocks = getBlocksOfPlainText(plainText) # returns an array
    
    for block in plainTextBlocks:
        cipherText += encryptBlock(block, numberOfRounds)
    
    endTime = time.time()
    
    print("Encrypted Text: " + cipherText)
    print("\nEncryption Time: " + str(endTime - startTime) + " seconds\n")
    


def encryptText():
    print("Enter the key: ", end="")
    key = input()
    key = formatKey(key)
    
    print("Enter the plain text: ", end="")
    plainText = input()
    
    print("Enter the bit version(128 or 192 or 256): ", end="")
    version = int(input())
    
    numberOfRounds = 10
    
    if version == 128:
        numberOfRounds = 10
    elif version == 192:
        numberOfRounds = 12
    elif version == 256:
        numberOfRounds = 14
    else:
        print("Invalid version!!!")
        exit(1)
        
    encrypt(key, plainText, numberOfRounds)


def makeCipherBlock(text):
    block = []
    for i in range(4):
     block.append([])
     for j in range(4):
         block[i].append(" ")
    
    index = 0
    for j in range(0, 4):
        for i in range(0, 4):
            # print(text[index], hex(ord(text[index])))
            block[i][j] = text[index : index+2]
            # print(block[i][j])
            index += 2

    # print("Cipher block:")
    # for i in range(4):
    #     print(block[i])
    return block
    
    
def getBlocksOfCipherText(cipherText):
    blocks = []
    
    numberOfBlocks = len(cipherText) // 32
    # print(numberOfBlocks)
    for i in range(0, numberOfBlocks):
        blocks.append(makeCipherBlock(cipherText[i*32 : (i+1)*32]))
        
    return blocks
    
    
def inverseShiftRow(stateMatrix):
    for i in range(1, 4):
        for j in range(i):
            popedItem = stateMatrix[i][3]
            stateMatrix[i].pop(3)
            stateMatrix[i].insert(0, popedItem)

    return stateMatrix


def inverseSubstituteBytes(stateMatrix):
    for i in range(4):
        for j in range(4):
            stateMatrix[i][j] = hex(InvSbox[int(stateMatrix[i][j], 16)])
            
    # for i in range(4):
    #     print(stateMatrix[i])
    return stateMatrix


def inverseMixColumn(stateMatrix):
    newStateMatrix = []
    for i in range(4):
     newStateMatrix.append([])
     for j in range(4):
         newStateMatrix[i].append(" ")
    
    fixedMatrix = []
    fixedMatrix.append([14, 11, 13, 9])
    fixedMatrix.append([9, 14, 11, 13])
    fixedMatrix.append([13, 9, 14, 11])
    fixedMatrix.append([11, 13, 9, 14])
    
    # print("newStateMatrix:", newStateMatrix)
    
    AES_modulus = BitVector(bitstring='100011011')
    
    for j in range(4):
        for rowOfFixedMatrix in range(4):
            xoredValue = 0
            for colOfFixedMatrix in range(4):
                bv1 = BitVector(intVal=fixedMatrix[rowOfFixedMatrix][colOfFixedMatrix])
                bv2 = BitVector(hexstring=stateMatrix[colOfFixedMatrix][j][2:])
                # print(fixedMatrix[rowOfFixedMatrix][colOfFixedMatrix], stateMatrix[colOfFixedMatrix][j])
                bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
                
                xoredValue = xoredValue ^ int(bv3)
                # print("xoredValue", hex(xoredValue))  
                
            newStateMatrix[rowOfFixedMatrix][j] = hex(xoredValue)
                
    # print("newStateMatrix:")
    # for i in range(4):
    #     print(newStateMatrix[i])
         
    return newStateMatrix

    
def decryptBlock(stateMatrix, numberOfRounds):
    roundKey = roundKeys[numberOfRounds]
    
    # last round
    stateMatrix = addRoundKey(stateMatrix, roundKey)
    
    # Round (numberOfRounds - 1) to 1
    for i in range(numberOfRounds-1, 0, -1):
        stateMatrix = inverseShiftRow(stateMatrix)
        stateMatrix = inverseSubstituteBytes(stateMatrix)
        roundKey = roundKeys[i]
        stateMatrix = addRoundKey(stateMatrix, roundKey)
        stateMatrix = inverseMixColumn(stateMatrix)
        
    stateMatrix = inverseShiftRow(stateMatrix)
    stateMatrix = inverseSubstituteBytes(stateMatrix)
    roundKey = roundKeys[0]
    stateMatrix = addRoundKey(stateMatrix, roundKey)
    
    plainText = ""
    for j in range(4):
        for i in range(4):
            plainText += chr(int(stateMatrix[i][j], 16))

    return plainText
    
def decrypt(key, cipherText, numberOfRounds):
    generateRoundConstants()
    
    startTime = time.time()
    generateAllTheRoundKeys(key, numberOfRounds)
    print("\nKey Scheduling Time: " + str(time.time() - startTime) + " seconds\n")
    
    startTime = time.time()
    
    plainText = ""
    cipherTextBlocks = getBlocksOfCipherText(cipherText)
    
    for block in cipherTextBlocks:
        plainText += decryptBlock(block, numberOfRounds)
    
    endTime = time.time()
    
    print("Decrypted Text: " + plainText)
    print("\nDecryption Time: " + str(endTime - startTime) + " seconds\n")



def decryptText():
    print("Enter the key: ", end="")
    key = input()
    key = formatKey(key)
    
    print("Enter the cipher text: ", end="")
    cipherText = input()
    
    print("Enter the bit version(128 or 192 or 256): ", end="")
    version = int(input())
    
    numberOfRounds = 10
    
    if version == 128:
        numberOfRounds = 10
    elif version == 192:
        numberOfRounds = 12
    elif version == 256:
        numberOfRounds = 14
    else:
        print("Invalid version!!!")
        exit(1)
        
    decrypt(key, cipherText, numberOfRounds)

    

def encryptFile(key, filePath, numberOfRounds):
    fileContent = open(filePath, "r").read()
    print(fileContent)
    encrypt(key, fileContent, numberOfRounds)
    
    
def decryptFile(key, filePath, numberOfRounds):
    fileContent = open(filePath, "r").read()
    decrypt(key, fileContent, numberOfRounds)
    

encryptText()
