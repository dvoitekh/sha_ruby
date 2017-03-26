require 'openssl'
Dir['./lib/*.rb'].each { |f| require f }

# encryption
# 1. sha
hash = ShaDigest.new('input.txt').perform

# 2. table transposition encryption
key = 10 + ((5 + 32) % 7)
cipher = TranspositionCipher.new(hash, key).encrypt
p 'Transposition encrypted cipher:'
p cipher

# 3. rsa key encryption
pair = OpenSSL::PKey::RSA.new 2048
a = pair.public_encrypt(key.to_s(16))

# decryption
# 1. rsa decryption
b = pair.private_decrypt(a).to_i(16)

# 2. table transposition decryption
restored_hash = TranspositionCipher.new(cipher, b).decrypt
p 'Transposition decrypted cipher:'
p restored_hash
