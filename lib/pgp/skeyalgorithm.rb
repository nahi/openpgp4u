# Copyright 2004  NAKAMURA, Hiroshi <nakahiro@sarion.co.jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


module PGP


module SKeyAlgorithm
  ALGORITHMS = {
    0 => ["Plaintext or unencrypted data"],
    1 => ["IDEA"],
    2 => ["Triple-DES (DES-EDE, as per spec - 168 bit key derived from 192)", 8],
    3 => ["CAST5 (128 bit key, as per RFC 2144)", 8],
    4 => ["Blowfish (128 bit key, 16 rounds)"],
    5 => ["Reserved"],
    6 => ["Reserved"],
    7 => ["AES with 128-bit key"],
    8 => ["AES with 192-bit key"],
    9 => ["AES with 256-bit key"],
    10 => ["Twofish with 256-bit key"],
    100 => ["Private/Experimental algorithm"],
    101 => ["Private/Experimental algorithm"],
    102 => ["Private/Experimental algorithm"],
    103 => ["Private/Experimental algorithm"],
    104 => ["Private/Experimental algorithm"],
    105 => ["Private/Experimental algorithm"],
    106 => ["Private/Experimental algorithm"],
    107 => ["Private/Experimental algorithm"],
    108 => ["Private/Experimental algorithm"],
    109 => ["Private/Experimental algorithm"],
    110 => ["Private/Experimental algorithm"],
  }

  def self.include?(algorithm)
    ALGORITHMS.key?(algorithm)
  end

  def self.label(algorithm)
    if data = ALGORITHMS[algorithm]
      data[0]
    else
      raise "Not supported: #{algorithm}"
    end
  end

  def self.blocksize(algorithm)
    if data = ALGORITHMS[algorithm]
      data[1]
    else
      raise "Not supported: #{algorithm}"
    end
  end

  def self.decrypt(algorithm, key, cipher, mode = :openpgp_cfb)
    case algorithm
    when 2
      if mode == :openpgp_cfb
        tripledes_decrypt_openpgp_cfb(key, cipher)
      else
        tripledes_decrypt(key, cipher)
      end
    else
      raise "Not supported: #{seckeypacket.algorithm}"
    end
  end

  def self.tripledes_decrypt_openpgp_cfb(key, cipher)
    crypt = OpenSSL::Cipher::Cipher.new("DES-EDE3")
    crypt.key = key
    crypt.padding = 0
    bs = 8
    header = cipher[0, 10]
    data = cipher[10..-1]
    lastiv = iv = "\000" * 8
    unused = 0
    result1, lastiv, iv, unused = cfb_decrypt(crypt, bs, lastiv, iv, unused, header)
    lastiv = iv
    # Unlike the Symmetrically Encrypted Data Packet, no special CFB
    # resynchronization is done after encrypting this prefix data.
    iv = openpgp_cfb__sync(lastiv, iv, unused, bs); unused = 0
    result2, lastiv, iv, unused = cfb_decrypt(crypt, bs, lastiv, iv, unused, data)
    result1 + result2
  end

  def self.cfb_decrypt(crypt, bs, lastiv, iv, unused, cipher)
    nbytes = cipher.size
    pos = 0
    result = []
    if nbytes <= unused
      raise
    end

    if unused > 0
      nbytes -= unused
      for idx in 0..(unused-1)
        temp = cipher[pos]; pos += 1
        result << (iv[idx + bs - unused] ^ temp)
        iv[idx + bs - unused] = temp
      end
    end

    while nbytes >= bs
      lastiv = iv.dup
      crypt.encrypt
      iv = crypt.update(iv); raise unless crypt.final.empty?
      for idx in 0..(bs-1) do
        temp = cipher[pos]; pos += 1
        result << (iv[idx] ^ temp)
        iv[idx] = temp
      end
      nbytes -= bs
    end

    if nbytes > 0
      lastiv = iv.dup
      crypt.encrypt
      iv = crypt.update(iv); raise unless crypt.final.empty?
      unused = bs - nbytes
      for idx in 0..(nbytes-1) do
        temp = cipher[pos]; pos += 1
        result << (iv[idx] ^ temp)
        iv[idx] = temp
      end
    end
    return [result.pack("C*"), lastiv, iv, unused]
  end

  def self.openpgp_cfb_sync(lastiv, iv, unused, bs)
    if unused > 0
      (lastiv + iv)[unused, bs]
    else
      raise
    end
  end

  def self.tripledes_decrypt(key, cipher)
    require 'openssl'
    crypt = OpenSSL::Cipher::Cipher.new("DES-EDE3-CFB")
    crypt.decrypt
    crypt.key = key
    crypt.iv = "\000" * 8
    crypt.padding = 0
    plain = crypt.update(cipher)
    raise unless crypt.final.empty?
    plain
  end
end


end
