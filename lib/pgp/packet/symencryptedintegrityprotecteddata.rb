require 'pgp/packet/packet'
require 'pgp/pkeyalgorithm'


module PGP
module Packet


class SymEncryptedIntegrityProtectedData < Packet
  def initialize(version = 1)
    super(18)
    @version = version
    @cipher = nil
  end

  attr_accessor :cipher

  attr_accessor :plain

  def scan(io)
    super
    io.puts "Encrypted data + MDC SHA1(20 bytes)"
  end

  def decrypt(algo, key)
    block = SKeyAlgorithm.decrypt(algo, key, @cipher, :normal_cfb)
    header = block[0, 10]
    body = block[10, block.size - 10 - 22]
    mdcheader = block[-22, 2]
    mdcbody = block[-20..-1]
    require 'digest/sha1'
    if Digest::SHA1.digest(header + body + mdcheader) != mdcbody
      raise "MDC check failed"
    end
    @plain = body
  end

private

  def dump_body
    raise "ToDo"
  end

  def self.loader(port, length)
    initpos = port.readlength
    version = load_version(port)
    packet = new(version)
    packet.cipher = port.read(length - (port.readlength - initpos))
    packet
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  def self.load_version(port)
    load_1octet(port)
  end

  add_loader(18, method(:loader))
  add_scanner(18, method(:scanner))
end


end
end


if __FILE__ == $0
  include PGP
  require 'pgp/packet/tstbase'
  include Packet::TstBase

  require 'pgp/pkeyalgorithm'
  require 'pgp/mpi'
  require 'openssl'
  require 'pgp/hexdump'

  def cfb_encrypt(algo, key, data)
    header = Util.random_bytes(8)
    header << header[6, 2]
    cipher = OpenSSL::Cipher::Cipher.new(algo)
    cipher.key = key
    cipher.padding = 0
    bs = 8
    # step 1
    fr = "\000" * bs
    # step 2
    cipher.encrypt
    p fr
    fre = cipher.update(fr); raise unless cipher.final.empty?
    # step 3
    result = []
    for i in 0..(bs - 1) do
      result << (fre[i] ^ header[i])
    end
    # step 4
    fr = result.pack("C*")
    # step 5
    cipher.encrypt
    fre = cipher.update(fr); raise unless cipher.final.empty?
    # step 6
    result << (fre[0] ^ header[bs - 1])
    result << (fre[1] ^ header[bs])
    # step 7
    fr = result.pack("C*")[2..-1]
    # step 8
    cipher.encrypt
    fre = cipher.update(fr); raise unless cipher.final.empty?
    # step 9
    pos = 0
    while pos < data.length
      for i in 0..(bs - 1) do
        break if data[pos].nil?
        result << (fre[i] ^ data[pos])
        pos += 1
      end
      # step 10
      fr = result[(pos - bs) + bs + 2, bs].pack("C*")
      # step 11
      cipher.encrypt
      fre = cipher.update(fr); raise unless cipher.final.empty?
    end
    result.pack("C*")
  end

  def cfb_decrypt(algo, key, data)
    cipher = OpenSSL::Cipher::Cipher.new(algo)
    cipher.key = key
    cipher.padding = 0
    header = data[0, 10]
    body = data[10..-1]
    bs = 8
    # step 1
    fr = "\000" * bs
    # step 2
    cipher.encrypt
    fre = cipher.update(fr); raise unless cipher.final.empty?
    # step 3
    result = []
    for i in 0..(bs - 1) do
      result << (fre[i] ^ header[i])
    end
    # step 4
    fr = header[0, bs]
    # step 5
    cipher.encrypt
    fre = cipher.update(fr); raise unless cipher.final.empty?
    # step 6
    result << (fre[0] ^ header[bs - 1])
    result << (fre[1] ^ header[bs])
    # step 7
    fr = header[2, bs]
    # step 8
    cipher.encrypt
    fre = cipher.update(fr); raise unless cipher.final.empty?
    # step 9
    pos = 0
    while pos < body.length
      for i in 0..(bs - 1) do
        break if body[pos].nil?
        result << (fre[i] ^ body[pos])
        pos += 1
      end
      # step 10
      fr = body[(pos - bs), bs]
      # step 11
      cipher.encrypt
      fre = cipher.update(fr); raise unless cipher.final.empty?
    end
    result.pack("C*")[10..-1]
  end

  def foo(key, lastiv, iv, unused, data)
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

  text = "123456789"
  key2 = Util.random_bytes(24)
  cipher = cfb_encrypt("DES-EDE3", key2, text)
  plain = cfb_decrypt("DES-EDE3", key2, cipher)
  p [cipher, plain]
  #exit

  m = SEC_SUBKEY.decrypt(MSG_SESSKEY.sessionkey)
  alg, key = PKeyAlgorithm.decode_sessionkey(MPI.to_bytes(m))
  msg = MSG_DATA.cipher
  puts HexDump.encode(key)

  p "--------"
  puts HexDump.encode(msg)
  puts HexDump.encode(cfb_decrypt("DES-EDE3", key2, msg))
  p "--"

  #msg = cipher; key = key2
  header = msg[0, 10]
  data = msg[10..-1]

  lastiv = iv = "\000" * 8
  unused = 0
  result1, lastiv, iv, unused = foo(key, lastiv, iv, unused, header)
  lastiv = iv
  # Unlike the Symmetrically Encrypted Data Packet, no special CFB
  # resynchronization is done after encrypting this prefix data.
  #iv = cipher_sync(lastiv, iv, unused)
  #unused = 0
  result2, lastiv, iv, unused = foo(key, lastiv, iv, unused, data)
  puts HexDump.encode(result1 + result2)
  p "-"
  cipher = OpenSSL::Cipher::Cipher.new("DES-EDE3-CFB")
  cipher.decrypt
  cipher.key = key
  cipher.iv = "\000" * 8
  cipher.padding = 0
  puts HexDump.encode(cipher.update(msg) + cipher.final)

  target = result2[0, result2.size - 20]
  mdc = result2[-20..-1]
  if Digest::SHA1.digest(result1 + target) != mdc
    raise "MDC check failed"
  end
  require 'zlib'
  z = Zlib::Inflate.new(-15)
  p "--"
  puts HexDump.encode(z.inflate(target[2..-1]) + z.finish)

  p "/////"

  m = SEC_SUBKEY.decrypt(MSG_SESSKEY.sessionkey)
  algo, key = PKeyAlgorithm.decode_sessionkey(MPI.to_bytes(m))
  MSG_DATA.decrypt(algo, key)
  com = PGP::Packet::Packet.load(MSG_DATA.plain)
  lit = com[0].body
  p PGP::Packet::Packet.load(lit)
  puts PGP::Packet::Packet.load(lit)[0].body
end
