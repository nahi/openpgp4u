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
