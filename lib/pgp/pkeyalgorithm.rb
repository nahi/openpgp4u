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


module PKeyAlgorithm
  ALGORITHMS = {
    1 => ["RSA (Encrypt or Sign)", 1],
    2 => ["RSA Encrypt-Only", 0],
    3 => ["RSA Sign-Only", 1],
    16 => ["Elgamal (Encrypt-Only)"],
    17 => ["DSA (Digital Signature Standard)", 2],
    18 => ["Reserved for Elliptic Curve"],
    19 => ["Reserved for ECDSA"],
    20 => ["Elgamal (Encrypt or Sign)"],
    21 => ["Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)"],
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

  def self.dump_summary(algorithm)
    "PKey algorithm - #{label(algorithm)}(#{algorithm})"
  end

  def self.dump_signature(algorithm, signature)
    case algorithm
    when 1, 3
      "m**d mod n - #{MPI.nbits(signature)} bits"
    when 17
      "r - #{MPI.nbits(signature[0])} bits, s - #{MPI.nbits(signature[1])} bits"
    when 16, 20
      "??? (#{signature.size} bytes)"
    else
      raise "Not supported: #{algorithm}"
    end
  end

  def self.dump_sessionkey(algorithm, sessionkey)
    case algorithm
    when 1, 2
      "m**e mod n - #{MPI.nbits(sessionkey)} bits"
    when 16
      "m * y**k mod p - #{MPI.nbits(sessionkey)} bits"
    else
      raise "Not supported: #{algorithm}"
    end
  end

  def self.signaturesize(algorithm)
    if data = ALGORITHMS[algorithm]
      data[1]
    else
      raise "Not supported: #{algorithm}"
    end
  end

  def self.encode_hash(algorithm, bits, hashalgorithm, hash)
    case algorithm
    when 1, 2, 3
      encode_hash_rsa(bits, hashalgorithm, hash)
    else
      raise "Not supported: #{algorithm}"
    end
  end

  def self.decode_hash(algorithm, bits, hashalgorithm, hash)
    case algorithm
    when 1, 2, 3
      decode_hash_rsa(bits, hashalgorithm, hash)
    else
      raise "Not supported: #{algorithm}"
    end
  end

  def self.encode_sessionkey(nbits, algorithm, sessionkey)
    nbytes = (nbits + 7) / 8
    checksum = Util.checksum(sessionkey)
    random = Util.random_bytes(nbytes - 4 - sessionkey.size - 2, true)
    "\000\002#{random}\000#{[algorithm].pack("C")}" +
      "#{sessionkey}#{MPI.to_bytes(checksum)}"
  end

  def self.decode_sessionkey(data)
    rnd, algorithm, rest = data.scan(/\A\000\002([^\000]+)\000([\x00-\xff])([\x00-\xff]*)\z/)[0]
    algorithm = algorithm.unpack("C")[0]
    sessionkey = rest[0..-3]
    checksum = MPI.from_bytes(rest[-2..-1])
    if Util.checksum(sessionkey) != checksum
      raise "Illegal checksum"
    end
    return [algorithm, sessionkey]
  end

  def self.secret_encrypt(seckeypacket, plain)
    case seckeypacket.algorithm
    when 1, 3
      rsa_secret(seckeypacket, plain)
    else
      raise "Not supported: #{seckeypacket.algorithm}"
    end
  end

  def self.secret_decrypt(seckeypacket, cipher)
    case seckeypacket.algorithm
    when 1, 2
      rsa_secret(seckeypacket, cipher)
    else
      raise "Not supported: #{seckeypacket.algorithm}"
    end
  end

  def self.public_encrypt(pubkeypacket, plain)
    case pubkeypacket.algorithm
    when 1, 2
      rsa_public(pubkeypacket, plain)
    else
      raise "Not supported: #{pubkeypacket.algorithm}"
    end
  end

  def self.public_decrypt(pubkeypacket, cipher)
    case pubkeypacket.algorithm
    when 1, 3
      rsa_public(pubkeypacket, cipher)
    else
      raise "Not supported: #{pubkeypacket.algorithm}"
    end
  end

  # v = M^d (mod n)
  # =>
  #   M1 = M ^ (d (mod p-1)) (mod p)
  #   M2 = M ^ (d (mod q-1)) (mod q)
  #   M3 = u * (M2 - M1) (mod q)
  #   v = M1 + M3 * p
  def self.rsa_secret(packet, input)
    require 'openssl'
    input = OpenSSL::BN.new(input)
    d = OpenSSL::BN.new(packet.d)
    p = OpenSSL::BN.new(packet.p)
    q = OpenSSL::BN.new(packet.q)
    u = OpenSSL::BN.new(packet.u)
    m1 = input.mod_exp(d % (p - 1), p)
    m2 = input.mod_exp(d % (q - 1), q)
    m3 = u.mod_mul(m2 - m1, q)
    (m1 + m3 * p).to_i
  end

  # M^e (mod n)
  def self.rsa_public(packet, input)
    require 'openssl'
    input = OpenSSL::BN.new(input)
    e = OpenSSL::BN.new(packet.e)
    n = OpenSSL::BN.new(packet.n)
    (input.mod_exp(e, n)).to_i
  end

  def self.encode_hash_rsa(rsabits, hashalgorithm, hash)
    len = (rsabits + 7) / 8
    if hash.size != HashAlgorithm.hashlength(hashalgorithm)
      raise "Illegal hash size"
    end
    asnoid = HashAlgorithm.asnoid(hashalgorithm)
    padlen = len - 2 - 1 - asnoid.size - hash.size
    "\000" + "\001" + "\xff" * padlen + "\000" + asnoid + hash
  end

  def self.decode_hash_rsa(rsabits, hashalgorithm, encoded)
    hashsize = HashAlgorithm.hashlength(hashalgorithm)
    encoded[-hashsize .. -1]
  end
end


end
