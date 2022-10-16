from itertools import permutations

class VigenereCipher:
    def __init__(self):
        self.key_set = {}
        with open('stringsets.txt', 'r') as file:
            lines = file.readlines()
            for line in lines:
                key, random_string = line.strip().split()
                temp = {}
                for i in range(len(random_string)):
                    key_text = random_string[i+1:len(random_string)] + random_string[0:i]
                    temp[random_string[i]] = key_text
                self.key_set[key] = temp
        self.given_p = "THISCIPHERWASWIDELYUSEDBECAUSEOFSIMPLESTRUCTURE"
        self.given_c = "OYKWUXRNJOOPPTXCTYNYQHFCQNIIWNKPAZQSTIFHOOWEYEHDQQYZMFQDHGZWUQIEZOUJNCEHDQQERBNJKRMRGLWIXVLVPFOBLLAVOPZENPADJPKVMMMPDYXJCBWEX "




    def encrypt(self, plaintext, keys, offset):
        expanded_key = keys * (len(plaintext) // len(keys)) + keys[:len(plaintext) % len(keys)]
        ciphertext = ""
        for i in range(len(plaintext)):
            ciphertext += self.key_set[expanded_key[i]][plaintext[i]][offset-1]
        return ciphertext

    def guess_encrypt(self, plaintext, keys, offset, desired_ciphertext):
        for i in range(len(plaintext)):
            if self.key_set[keys[i]][plaintext[i]][offset - 1] != desired_ciphertext[i]:
                return False
        return True

    def narrow_down(self, n=4, start=0):
        available_key_offset_pair_at_length_n = {}
        for i in range(1, n+1):
            available_key_offset_pair_at_length_n[i] = []

        # construction of pairs at length 1
        for key in self.key_set.keys():
            for offset in range(1, 26):
                if self.key_set[key][self.given_p[start]][offset - 1] == self.given_c[start]:
                    available_key_offset_pair_at_length_n[1].append(([key], offset))

        for key_len in range(2, n+1):
            for keys, offset in available_key_offset_pair_at_length_n[key_len-1]:
                for key in self.key_set.keys():
                    if key not in keys:
                        if self.key_set[key][self.given_p[start+key_len-1]][offset - 1] == self.given_c[start+key_len-1]:
                            nk = keys + [key]
                            available_key_offset_pair_at_length_n[key_len].append((nk, offset))

        key_set = self.make_unique_key_set(available_key_offset_pair_at_length_n[n], False)
        return key_set

    def make_unique_key_set(self, k_list, offset_given):
        uk_set = set()
        if offset_given:
            for keys in k_list:
                uk_set.add(" ".join(keys))
        else:
            for keys, offset in k_list:
                uk_set.add(" ".join(keys) + " /" + str(offset))
        return uk_set

    def narrow_down_offset(self, n=4, start=0, offset=6):
        available_key_at_length_n = {}
        for i in range(1, n+1):
            available_key_at_length_n[i] = []

        # construction of pairs at length 1
        for key in self.key_set.keys():
            if self.key_set[key][self.given_p[start]][offset - 1] == self.given_c[start]:
                available_key_at_length_n[1].append([key])

        for key_len in range(2, n+1):
            for keys in available_key_at_length_n[key_len-1]:
                for key in self.key_set.keys():
                    if key not in keys:
                        if self.key_set[key][self.given_p[start+key_len-1]][offset - 1] == self.given_c[start+key_len-1]:
                            nk = keys + [key]
                            available_key_at_length_n[key_len].append(nk)

        key_set = self.make_unique_key_set(available_key_at_length_n[n], True)
        return key_set

    def decrypt(self, keys, offset, block, block_size):
        start = block_size * (block-1)
        end = len(keys)
        ciphertext = self.given_c[start:start+end]
        plaintext = ""
        for i in range(len(keys)):
            plaintext += self.key_set[keys[i]][ciphertext[i]][-offset]
        return plaintext
