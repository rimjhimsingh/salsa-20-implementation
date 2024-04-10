
import sys
class salsa20:
    sigma = b"expand 32-byte k"
    
    @staticmethod
    def quarterround(y0, y1, y2, y3):
        
        def rotl(a, b):
            return ((a << b) & 0xffffffff) | (a >> (32 - b))

        z1 = y1 ^ rotl((y0 + y3) % 2**32, 7)
        z2 = y2 ^ rotl((z1 + y0) % 2**32, 9)
        z3 = y3 ^ rotl((z2 + z1) % 2**32, 13)
        z0 = y0 ^ rotl((z3 + z2) % 2**32, 18)
        return z0, z1, z2, z3
    
    @staticmethod
    def rowround(y):
    
        if len(y) != 16:
            raise ValueError("Input must be a sequence of 16 words.")
        
        z = [0] * 16
        z[0], z[1], z[2], z[3] = salsa20.quarterround(y[0], y[1], y[2], y[3])
        z[5], z[6], z[7], z[4] = salsa20.quarterround(y[5], y[6], y[7], y[4])
        z[10], z[11], z[8], z[9] = salsa20.quarterround(y[10], y[11], y[8], y[9])
        z[15], z[12], z[13], z[14] = salsa20.quarterround(y[15], y[12], y[13], y[14])
        
        return z
    
    @staticmethod
    def columnround(x):
    
        if len(x) != 16:
            raise ValueError("Input must be a sequence of 16 words.")
        
        y = [0] * 16
        y[0], y[4], y[8], y[12] = salsa20.quarterround(x[0], x[4], x[8], x[12])
        y[5], y[9], y[13], y[1] = salsa20.quarterround(x[5], x[9], x[13], x[1])
        y[10], y[14], y[2], y[6] = salsa20.quarterround(x[10], x[14], x[2], x[6])
        y[15], y[3], y[7], y[11] = salsa20.quarterround(x[15], x[3], x[7], x[11])
        
        return y
    
    @staticmethod
    def doubleround(x):
  
        column_round_result = salsa20.columnround(x)
        row_round_result = salsa20.rowround(column_round_result)
        return row_round_result
    
    @staticmethod
    def littleendian(b0, b1, b2, b3):
    
        return (b0 & 0xff) | ((b1 & 0xff) << 8) | ((b2 & 0xff) << 16) | ((b3 & 0xff) << 24)
    
    @staticmethod
    def inverse_littleendian(word):
        
        b0 = word & 0xFF
        b1 = (word >> 8) & 0xFF
        b2 = (word >> 16) & 0xFF
        b3 = (word >> 24) & 0xFF
        return bytes([b0, b1, b2, b3])  
    
    @staticmethod
    def salsa20_expansion(k, n):
        
        sigma = (b"expand 32-byte k", b"expand 16-byte k")

        if len(k) == 32:
            k0, k1 = k[:16], k[16:]
            constants = (sigma[0][:4], sigma[0][4:8], sigma[0][8:12], sigma[0][12:16])
        elif len(k) == 16:
            k0, k1 = k, k
            constants = (sigma[1][:4], sigma[1][4:8], sigma[1][8:12], sigma[1][12:16])
        elif len(k) ==8:
            a1 = (101,120,112,97)
            a2 = (110,100,32,48)
            a3 = (56, 45,98,121)
            a4 = (116,101,32,107)
            expanded_key = bytes(a1) + 2*k + bytes(a2) + n+ bytes(a3) + 2*k + bytes(a4)
            return expanded_key

            
        else : raise ValueError("Key must be 16 or 32 bytes in length.")

        expanded_key = (
            constants[0] +
            k0 +
            constants[1] +
            n +
            constants[2] +
            k1 +
            constants[3]
        )

        return expanded_key
    
    @staticmethod
    def salsa20_hash(input_bytes):
        if len(input_bytes) != 64:
            raise ValueError("Input must be exactly 64 bytes long.")
        
        state = [salsa20.littleendian(input_bytes[i], input_bytes[i+1], input_bytes[i+2], input_bytes[i+3]) for i in range(0, 64, 4)]
        
        initial_state = state.copy()
        
        for _ in range(6):
            state = salsa20.doubleround(state)
        
        output_state = [(state[i] + initial_state[i]) & 0xFFFFFFFF for i in range(16)]
        
        output_bytes = bytearray()
        for word in output_state:
            output_bytes.extend(salsa20.inverse_littleendian(word))
        
        return output_bytes

    @staticmethod
    def encrypt(key, nonce, plaintext):
        ciphertext = bytearray()
        blocks = (len(plaintext) + 63) // 64  
        
        for block_index in range(blocks):
            block_counter = block_index.to_bytes(8, 'little')
            nonce_block = nonce[:8] + block_counter 
            expanded_key = salsa20.salsa20_expansion(key, nonce_block)
            key_stream = salsa20.salsa20_hash(expanded_key)
            
            block_start = block_index * 64
            block_end = min(block_start + 64, len(plaintext))
            for i in range(block_start, block_end):
                ciphertext.append(plaintext[i] ^ key_stream[i - block_start])
        
        return ciphertext

def main():
    keysize = int(sys.argv[1])
    key_hex = sys.argv[2]
    nonce_hex = sys.argv[3]
    input_text = sys.argv[4]

    key = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(nonce_hex)
    input = bytes.fromhex(input_text)

    salsaobj = salsa20()
    output = salsaobj.encrypt(key, nonce, input)
    print(output.hex())

    
if __name__ == "__main__":
    main()