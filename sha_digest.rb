require 'digest/sha1'

class ShaDigest
  BLOCK_LEN = 512
  BLOCK_DATA_MAX_LEN = 448

  def initialize(file)
    @text = File.read(file)
    @sha_vars = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
  end

  def perform
    preprocessed_blocks.each do |block|
      a, b, c, d, e = @sha_vars
      w = (block.scan(/.{1,32}/).map { |v| v.to_i(2) } + [0] * 64).flatten

      for i in (16..79)
        w[i] = self.class.leftrotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)
      end

      w.length.times do |i|
        if i >= 0 && i <= 19
          f = (b & c) | (~b & d)
          k = 0x5A827999
        elsif i >= 20 && i <= 39
          f = b ^ c ^ d
          k = 0x6ED9EBA1
        elsif i >= 40 && i <= 59
          f = (b & c) | (b & d) | (c & d)
          k = 0x8F1BBCDC
        elsif i >= 60 && i <= 79
          f = b ^ c ^ d
          k = 0xCA62C1D6
        end

        a, b, c, d, e = (self.class.leftrotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF, a, self.class.leftrotate(b, 30), c, d
      end

      [a, b, c, d, e].each_with_index do |temp_var, i|
        @sha_vars[i] = (@sha_vars[i] + temp_var) & 0xFFFFFFFF
      end
    end

    print_results
  end

private

  def split_to_binary_blocks
    binary = @text.unpack('B*').first
    rest_len = binary.length % BLOCK_LEN
    blocks = binary.scan(/.{1,512}/)

    [blocks, binary.length, rest_len]
  end

  def preprocessed_blocks
    blocks, binary_len, rest_len = split_to_binary_blocks

    if rest_len < BLOCK_DATA_MAX_LEN
      blocks.last << '1'
      if BLOCK_DATA_MAX_LEN > rest_len
        blocks.last << '0' * (BLOCK_DATA_MAX_LEN - blocks.last.length)
      end
      blocks.last << binary_len.to_s(2).rjust(BLOCK_LEN - blocks.last.length, '0')
    else
      blocks.last << '1' + '0' * (BLOCK_LEN - blocks.last.length)
      blocks << binary_len.to_s(2).rjust(BLOCK_LEN, '0')
    end

    blocks
  end

  def print_results
    digest = @sha_vars.map { |var| var.to_s(16).rjust(8, '0') }.join
    pattern_digest = Digest::SHA1.hexdigest(@text)

    p 'Custom digest:'
    p digest
    p 'Digest::SHA1:'
    p pattern_digest
    p 'Match:'
    p digest == pattern_digest
  end

  def self.leftrotate(value, shift)
    ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF
  end
end
