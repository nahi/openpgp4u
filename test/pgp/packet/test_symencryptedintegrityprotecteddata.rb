require 'test/unit'
require 'pgp/packet'
require 'pgp/mpi'
require 'openssl'
require 'pgp/hexdump'


module TestPGP
module TestPacket


class TestSymEncryptedIntegrityProtectedData < Test::Unit::TestCase
  include PGP
  require File.join(File.expand_path(File.dirname(__FILE__)), 'testbase')
  include TestPGP::TestPacket::TestBase

  def test_key
    m = SEC_SUBKEY.decrypt(MSG_SESSKEY.sessionkey)
    algo, key = PKeyAlgorithm.decode_sessionkey(MPI.to_bytes(m))
    assert_equal(2, algo)
    keydump = [
      "00000000  7fb9a8a6 f9d363f4 85b63b0b 9798ec06   ......c...;.....",
      "00000010  e9d06c2b 008da0e9                     ..l+...."
    ]
    assert_equal(keydump, HexDump.encode(key))
  end

  def cipher_selfcfb(key, lastiv, iv, unused, data)
    cipher = OpenSSL::Cipher::Cipher.new("DES-EDE3")
    cipher.key = key
    cipher.padding = 0
    nbytes = data.size
    pos = 0
    result = []

    bs = 8
    if nbytes <= unused
      raise
    end

    if unused > 0
      nbytes -= unused
      for idx in 0..(unused-1)
        temp = data[pos]; pos += 1
        result << (iv[idx + bs - unused] ^ temp)
        iv[idx + bs - unused] = temp
      end
    end

    while nbytes >= bs
      lastiv = iv.dup
      cipher.encrypt
      iv = cipher.update(iv); raise unless cipher.final.empty?
      for idx in 0..(bs-1) do
        temp = data[pos]; pos += 1
        result << (iv[idx] ^ temp)
        iv[idx] = temp
      end
      nbytes -= bs
    end

    if nbytes > 0
      lastiv = iv.dup
      cipher.encrypt
      iv = cipher.update(iv); raise unless cipher.final.empty?
      unused = bs - nbytes
      for idx in 0..(nbytes-1) do
        temp = data[pos]; pos += 1
        result << (iv[idx] ^ temp)
        iv[idx] = temp
      end
    end
    return [result.pack("C*"), lastiv, iv, unused]
  end

  def cipher_sync(lastiv, iv, unused)
    bs = 8
    if unused > 0
      (lastiv + iv)[unused, bs]
    else
      raise
    end
  end

  def test_selfcfb
    # self decryption
    m = SEC_SUBKEY.decrypt(MSG_SESSKEY.sessionkey)
    algo, key = PKeyAlgorithm.decode_sessionkey(MPI.to_bytes(m))
    msg = MSG_DATA.cipher
    header = msg[0, 10]
    data = msg[10..-1]

    lastiv = iv = "\000" * 8
    unused = 0
    result1, lastiv, iv, unused = cipher_selfcfb(key, lastiv, iv, unused, header)
    lastiv = iv
    # Unlike the Symmetrically Encrypted Data Packet, no special CFB
    # resynchronization is done after encrypting this prefix data.
    #iv = cipher_sync(lastiv, iv, unused)
    #unused = 0
    result2, lastiv, iv, unused = cipher_selfcfb(key, lastiv, iv, unused, data)
    selfcfbresult = HexDump.encode(result1 + result2)

    # openssl decryption
    cipher = OpenSSL::Cipher::Cipher.new("DES-EDE3-CFB")
    cipher.decrypt
    cipher.key = key
    cipher.iv = "\000" * 8
    cipher.padding = 0
    opensslcfbresult = HexDump.encode(cipher.update(msg) + cipher.final)

    # compare
    assert_equal(opensslcfbresult, selfcfbresult)
  end

  def test_decrypt
    m = SEC_SUBKEY.decrypt(MSG_SESSKEY.sessionkey)
    algo, key = PKeyAlgorithm.decode_sessionkey(MPI.to_bytes(m))
    MSG_DATA.decrypt(algo, key)
    com = PGP::Packet::Packet.load(MSG_DATA.plain)
    lit = com[0].body
    assert_equal("hello world\r\n", PGP::Packet::Packet.load(lit)[0].body)
  end
end


end
end
