require 'pgp/packet/packet'
require 'pgp/pkeyalgorithm'
require 'pgp/hashalgorithm'
require 'pgp/packet/sigsubpacket'


module PGP
module Packet


class Signature < Packet
  TYPES = {
    0x00 => "Signature of a binary document",
    0x01 => "Signature of a canonical text document",
    0x02 => "Standalone signature",
    0x10 => "Generic certification of a User ID and Public Key packet",
    0x11 => "Persona certification of a User ID and Public Key packet",
    0x12 => "Casual certification of a User ID and Public Key packet",
    0x13 => "Positive certification of a User ID and Public Key packet",
    0x18 => "Subkey Binding Signature",
    0x1F => "Signature directly on a key",
    0x20 => "Key revocation signature",
    0x28 => "Subkey revocation signature",
    0x30 => "Certification revocation signature",
    0x40 => "Timestamp signature",
  }

  def self.typelabel(type)
    TYPES[type]
  end

  def initialize(type = nil, pkey_algorithm = nil, hash_algorithm = nil)
    super(2)
    self.type = type
    self.pkey_algorithm = pkey_algorithm
    self.hash_algorithm = hash_algorithm
    @version = 4
    @target = nil
    @signature = nil
    @secretkey = nil
    @hashedsubpacket = []
    @unhashedsubpacket = []
  end

  def scan(io)
    super
    io.puts "Sig type - #{typelabel}(#{@type})"
    io.puts PKeyAlgorithm.dump_summary(@pkey_algorithm)
    io.puts HashAlgorithm.dump_summary(@hash_algorithm)
  end

  attr_accessor :version
  attr_accessor :target
  attr_accessor :signature
  attr_accessor :secretkey

  def typelabel
    Signature.typelabel(@type)
  end

  def type
    @type
  end

  def type=(type)
    unless TYPES.key?(type)
      raise "Unknown type: #{type}"
    end
    @type = type
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

  def hashedsubpacket
    @hashedsubpacket
  end

  def unhashedsubpacket
    @unhashedsubpacket
  end

private

  def dump_body
    hashed_body = dump_version + dump_signature_type + dump_pkey_algorithm +
      dump_hash_algorithm + dump_hashedsubpacket
    hash = calc_hash(@target + dump_hash_magic(hashed_body))
    hashed_body + dump_unhashedsubpacket + dump_hash_quicktest(hash) +
      dump_signature(hash)
  end

  def dump_hash_magic(body)
    body + dump_2octet(0x04ff) + dump_4octet(body.size)
  end

  def dump_signature_type
    dump_1octet(@type)
  end

  def dump_pkey_algorithm
    dump_1octet(@pkey_algorithm)
  end

  def dump_hash_algorithm
    dump_1octet(@hash_algorithm)
  end

  def dump_hashedsubpacket
    subpacket = @hashedsubpacket.collect { |packet| packet.dump }.join
    dump_2octet(subpacket.length) + subpacket
  end

  def dump_unhashedsubpacket
    subpacket = @unhashedsubpacket.collect { |packet| packet.dump }.join
    dump_2octet(subpacket.length) + subpacket
  end

  def dump_hash_quicktest(hash)
    hash[0, 2]
  end

  def dump_signature(hash)
    unless @secretkey
      STDERR.puts("No secret key given: dumping dummy signature")
      return MPI.encode(0)
    end
    encoded_hash = PKeyAlgorithm.encode_hash(@pkey_algorithm, @secretkey.nbits,
      @hash_algorithm, hash)
    @signature = @secretkey.encrypt(MPI.from_bytes(encoded_hash))
    # should we check :collect instead of :each?
    if @signature.respond_to?(:each)
      result = ''
      @signature.each do |sig|
        result << MPI.encode(sig)
      end
      result
    else
      MPI.encode(@signature)
    end
  end

  def calc_hash(data)
    HashAlgorithm.calc(@hash_algorithm, data)
  end

  def self.loader(port, length)
    version = load_version(port)
    case version
    when 2, 3
      raise "ToDo"
    when 4
      loader_v4(port, length - 1)
    else
      raise "Unknown version: #{version}"
    end
  end

  def self.loader_v4(port, length)
    initpos = port.readlength
    signature_type = load_signature_type(port)
    pkey_algorithm = load_pkey_algorithm(port)
    hash_algorithm = load_hash_algorithm(port)
    packet = new(signature_type, pkey_algorithm, hash_algorithm)
    #
    sublength = load_2octet(port)
    sub = load_subpacket(port, sublength)
    packet.hashedsubpacket.replace(sub)
    #
    sublength = load_2octet(port)
    sub = load_subpacket(port, sublength)
    packet.unhashedsubpacket.replace(sub)
    qt = load_hash_quicktest(port)
    # ToDo: test qt
    packet.signature = load_signature(port,
      length - (port.readlength - initpos), pkey_algorithm)
    packet
  end

  def self.scanner(io, port, length)
    version = load_version(port)
    io.puts "Version - #{version}"
    case version
    when 2, 3
      scanner_v3(io, port, length - 1)
    when 4
      scanner_v4(io, port, length - 1)
    else
      raise "Unknown version: #{version}"
    end
  end

  def self.scanner_v3(io, port, length)
    require 'pgp/packet/signaturev3'
    initpos = port.readlength
    header_length = load_1octet(port)
    raise "Must be 5" if header_length != 5
    signature_type = load_signature_type(port)
    creation_time = load_time(port)
    keyid = port.read(8)
    pkey_algorithm = load_pkey_algorithm(port)
    hash_algorithm = load_hash_algorithm(port)
    qt = load_hash_quicktest(port)
    packet = SignatureV3.new(signature_type, pkey_algorithm, hash_algorithm)
    packet.creation_time = creation_time
    packet.keyid = keyid
    packet.scan(io)
    io.puts "Hash left 2 bytes - " + qt.unpack("H*")[0]
    io.puts "Signature: #{PKeyAlgorithm.label(pkey_algorithm)}"
    io.indent(4) do
      sig = load_signature(port,
        length - (port.readlength - initpos), pkey_algorithm)
      io.puts PKeyAlgorithm.dump_signature(pkey_algorithm, sig)
    end
  end

  def self.scanner_v4(io, port, length)
    initpos = port.readlength
    signature_type = load_signature_type(port)
    pkey_algorithm = load_pkey_algorithm(port)
    hash_algorithm = load_hash_algorithm(port)
    packet = new(signature_type, pkey_algorithm, hash_algorithm)
    packet.scan(io)
    io.puts "Hashed Sub:"
    io.indent(4) do
      sublength = load_2octet(port)
      scan_subpacket(io, port, sublength)
    end
    io.puts "Unhashed Sub:"
    io.indent(4) do
      sublength = load_2octet(port)
      scan_subpacket(io, port, sublength)
    end
    qt = load_hash_quicktest(port)
    io.puts "Hash left 2 bytes - " + qt.unpack("H*")[0]
    io.puts "Signature: #{PKeyAlgorithm.label(pkey_algorithm)}"
    io.indent(4) do
      sig = load_signature(port,
        length - (port.readlength - initpos), pkey_algorithm)
      io.puts PKeyAlgorithm.dump_signature(pkey_algorithm, sig)
    end
  end

  def self.load_version(port)
    version = load_1octet(port)
    if version != 2 and version != 3 and version != 4
      raise "Version #{version} signature packet not supported"
    end
    version
  end

  def self.load_signature_type(port)
    load_1octet(port)
  end

  def self.load_pkey_algorithm(port)
    load_1octet(port)
  end

  def self.load_hash_algorithm(port)
    load_1octet(port)
  end

  def self.load_subpacket(port, length)
    subpackets = []
    initpos = port.readlength
    while (port.readlength - initpos) < length
      subpackets << SigSubPacket::Packet.load(port)
    end
    if (port.readlength - initpos) != length
      raise "Illegal subpacket format"
    end
    subpackets
  end

  def self.scan_subpacket(io, port, length)
    initpos = port.readlength
    while (port.readlength - initpos) < length
      SigSubPacket::Packet.scan(port, io)
    end
    if (port.readlength - initpos) != length
      raise "Illegal subpacket format: #{port.readlength - initpos}/#{length}"
    end
  end

  def self.load_hash_quicktest(port)
    port.read(2)
  end

  def self.load_signature(port, length, algorithm)
    size = PKeyAlgorithm.signaturesize(algorithm)
    if size.nil?
      port.read(length)
    elsif size == 1
      MPI.load(port)
    else
      result = []
      size.times do
        result << MPI.load(port)
      end
      result
    end
  end

  add_loader(2, method(:loader))
  add_scanner(2, method(:scanner))
end


end
end
