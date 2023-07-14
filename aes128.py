Sbox = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
]


invSbox = [
    [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
    [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
    [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
    [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
    [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
    [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
    [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
    [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
    [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
    [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
    [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
    [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
    [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
    [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
    [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
]


Rcon = [[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
]


def mul_by_02(num):
    """ The function multiplies by 2 in Galua space. """    
    if num < 0x80:
        res = (num << 1)
    else:
        res = (num << 1) ^ 0x1B
    return res % 0x100


def mul_by_03(num):
    """ The function multiplies by 3 in Galua space. """
    return (mul_by_02(num) ^ num)


def mul_by_09(num):
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ num


def mul_by_0b(num):
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(num) ^ num


def mul_by_0d(num):
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(mul_by_02(num)) ^ num


def mul_by_0e(num):
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(mul_by_02(num)) ^ mul_by_02(num)


class AES():    
    def __init__(self):
        self.Nk = 4  # Nk - number of 32-bit words comprising the Cipher Key
        self.Nb = 4  # Nb - number of columns
        self.Nr = 10  # Nr - number of rounds
        self.State = None  # matrix of states
        self.key_schedule = None  # matrix of keys
        
    
    def encrypt(self, plaintext, key):
        self.State = None 
        self.key_schedule = None  
        
        # check whether the length of the key corresponds to the specified type
        if len(key) != 4 * self.Nk:
            raise AssertionError("Wrong key length!!!")
        
        # if the length of the plain text is not a multiple of the required value, then we supplement it
        for i in range(len(plaintext) % (4 * self.Nb)):
            plaintext = plaintext + bytes([1])
        
        return self.Cipher(plaintext, key)
        
    
    def decrypt(self, ciphertext, key):
        self.State = None 
        self.key_schedule = None  
        
        # check whether the length of the key corresponds to the specified type
        if len(key) != 4 * self.Nk:
            raise AssertionError("Wrong key length!!!")
        
        # if the length of the plain text is not a multiple of the required value, then we supplement it
        for i in range(len(ciphertext) % (4 * self.Nb)):
            cipher.append(0x01)
        
        return self.InvCipher(ciphertext, key)
        
        
    def init_state(self, input_bytes):
        # prepare our enter data (State array and KeySchedule)
        self.State = [[] for j in range(self.Nb)]
        for r in range(4):
            for c in range(self.Nb):
                self.State[r].append(input_bytes[r + 4 * c])
        
     
    def Cipher(self, input_bytes, key):
        self.init_state(input_bytes)
        self.KeyExpansion(key) 
        self.AddRoundKey()

        for rnd in range(1, self.Nr):
            self.SubBytes()
            self.ShiftRows()
            self.MixColumns()
            self.AddRoundKey(rnd)

        self.SubBytes()
        self.ShiftRows()
        self.AddRoundKey(rnd+1)

        output_bytes = [None for i in range(4 * self.Nb)]
        for r in range(4):
            for c in range(self.Nb):
                output_bytes[r + 4 * c] = self.State[r][c]
        return output_bytes
    
        
    def AddRoundKey(self, rnd=0):
        """That transformation combines State and KeySchedule together. Xor 
        of State and RoundSchedule(part of KeySchedule).
        """
        for col in range(self.Nk):
            for i in range(4):
                self.State[i][col] ^= self.key_schedule[i][self.Nb * rnd + col]
    
    
    def KeyExpansion(self, key):        
        """ The function makes list of RoundKeys for function AddRoundKey. """
        key_symbols = [symbol for symbol in key]

        # ChipherKey (which is base of KeySchedule)
        self.key_schedule = [[] for i in range(4)]
        for r in range(4):
            for c in range(self.Nk):
                self.key_schedule[r].append(key_symbols[r + 4 * c])

        # Continue to fill KeySchedule
        for col in range(self.Nk, self.Nb * (self.Nr + 1)):
            if col % self.Nk == 0:
                # take shifted (col - 1)th column
                tmp = [self.key_schedule[row][col - 1] for row in range(1, 4)]
                tmp.append(self.key_schedule[0][col - 1])

                # change its elements using Sbox-table like in SubBytes
                for j in range(len(tmp)):
                    tmp[j] = self.SubWord(tmp[j])

                # make XOR of 3 columns
                for row in range(4):
                    s = (self.key_schedule[row][col - 4]) ^ (tmp[row]) ^ (Rcon[row][int(col / self.Nk - 1)])
                    self.key_schedule[row].append(s)
            else:
                # make XOR of 2 columns
                for row in range(4):
                    s = self.key_schedule[row][col - 4] ^ self.key_schedule[row][col - 1]
                    self.key_schedule[row].append(s)

                    
    def SubBytes(self):
        for i in range(len(self.State)):
            for j in range(len(self.State[i])):
                row = self.State[i][j] // 0x10
                col = self.State[i][j] % 0x10
                self.State[i][j] = Sbox[row][col]
    
    
    def ShiftRows(self):
        for i in range(1, self.Nb):
            self.State[i] = self.State[i][i:] + self.State[i][:i]
    
    
    def SubWord(self, word):
        row = word // 0x10
        col = word % 0x10
        return Sbox[row][col]
    

    def MixColumns(self):
        for i in range(self.Nb):
            s0 = mul_by_02(self.State[0][i]) ^ mul_by_03(self.State[1][i]) ^ self.State[2][i] ^ self.State[3][i]
            s1 = self.State[0][i] ^ mul_by_02(self.State[1][i]) ^ mul_by_03(self.State[2][i]) ^ self.State[3][i]
            s2 = self.State[0][i] ^ self.State[1][i] ^ mul_by_02(self.State[2][i]) ^ mul_by_03(self.State[3][i])
            s3 = mul_by_03(self.State[0][i]) ^ self.State[1][i] ^ self.State[2][i] ^ mul_by_02(self.State[3][i])
            self.State[0][i] = s0
            self.State[1][i] = s1
            self.State[2][i] = s2
            self.State[3][i] = s3
    
    
    def InvCipher(self, input_bytes, key):
        """Function decrypts the cipher according to AES(128) algorithm using the key
        Args:
           cipher -- list of int less than 255, ie list of bytes
           key -- a strig of plain text. Do not forget it! The same string is used in decryption 
        Returns:
            List of int
        """

        self.init_state(input_bytes)
        self.KeyExpansion(key)
        self.AddRoundKey(self.Nr)

        rnd = self.Nr - 1
        while rnd >= 1:
            self.InvShiftRows()
            self.InvSubBytes()
            self.AddRoundKey(rnd)
            self.InvMixColumns()
            rnd -= 1

        self.InvShiftRows()
        self.InvSubBytes()
        self.AddRoundKey(rnd)

        output = [None for i in range(4 * self.Nb)]
        for r in range(4):
            for c in range(self.Nb):
                output[r + 4 * c] = self.State[r][c]

        return output
    
    
    def InvSubBytes(self):
        for i in range(len(self.State)):
            for j in range(len(self.State[i])):
                row = self.State[i][j] // 0x10
                col = self.State[i][j] % 0x10
                self.State[i][j] = invSbox[row][col]
                
                
    def InvShiftRows(self):
        for i in range(1, self.Nb):
            self.State[i] = self.State[i][-i:] + self.State[i][:-i]
            
    
    def InvMixColumns(self):
        for i in range(self.Nb):
            s0 = mul_by_0e(self.State[0][i]) ^ mul_by_0b(self.State[1][i]) ^ mul_by_0d(self.State[2][i]) ^ mul_by_09(self.State[3][i])
            s1 = mul_by_09(self.State[0][i]) ^ mul_by_0e(self.State[1][i]) ^ mul_by_0b(self.State[2][i]) ^ mul_by_0d(self.State[3][i])
            s2 = mul_by_0d(self.State[0][i]) ^ mul_by_09(self.State[1][i]) ^ mul_by_0e(self.State[2][i]) ^ mul_by_0b(self.State[3][i])
            s3 = mul_by_0b(self.State[0][i]) ^ mul_by_0d(self.State[1][i]) ^ mul_by_09(self.State[2][i]) ^ mul_by_0e(self.State[3][i])
            self.State[0][i] = s0
            self.State[1][i] = s1
            self.State[2][i] = s2
            self.State[3][i] = s3


