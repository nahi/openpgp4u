require 'pgp/packet/packet'
require 'pgp/pkeyalgorithm'
require 'pgp/hashalgorithm'
require 'pgp/packet/sigsubpacket'


module PGP
module Packet


class SignatureV3 < Packet
  def initialize(type = nil, pkey_algorithm = nil, hash_algorithm = nil)
    super(2)
    self.type = type
    self.pkey_algorithm = pkey_algorithm
    self.hash_algorithm = hash_algorithm
    @version = 3
    @creation_time = nil
    @keyid
  end

  def scan(io)
    super
    io.puts "Sig type - #{typelabel}(#{@type})"
    io.puts PKeyAlgorithm.dump_summary(@pkey_algorithm)
    io.puts HashAlgorithm.dump_summary(@hash_algorithm)
    io.puts "Creation time - #{@creation_time}"
    io.puts "Key ID - 0x#{keyid.unpack("H*")[0].upcase}"
  end

  attr_accessor :version
  attr_accessor :type
  attr_accessor :creation_time
  attr_accessor :keyid

  def typelabel
    Signature.typelabel(@type)
  end

  def pkey_algorithm=(pkey_algorithm)
    unless PKeyAlgorithm.include?(pkey_algorithm)
      raise "Unknown algorithm: #{pkey_algorithm}"
    end
    @pkey_algorithm = pkey_algorithm
  end

  def hash_algorithm=(hash_algorithm)
    unless HashAlgorithm.include?(hash_algorithm)
      raise "Unknown algorithm: #{hash_algorithm}"
    end
    @hash_algorithm = hash_algorithm
  end

private

  def dump_body
    raise "Not allowed"
  end
end


end
end
