require 'pgp/packet/support'


module PGP
module Packet
module SigSubPacket


class Packet
  include Support
  extend Support::ModuleSupport
  
  TYPES = {
    2 => "signature creation time",
    3 => "signature expiration time",
    4 => "exportable certification",
    5 => "trust signature",
    6 => "regular expression",
    7 => "revocable",
    9 => "key expiration time",
    10 => "placeholder for backward compatibility",
    11 => "preferred symmetric algorithms",
    12 => "revocation key",
    16 => "issuer key ID",
    20 => "notation data",
    21 => "preferred hash algorithms",
    22 => "preferred compression algorithms",
    23 => "key server preferences",
    24 => "preferred key server",
    25 => "primary user id",
    26 => "policy URL",
    27 => "key flags",
    28 => "signer's user id",
    29 => "reason for revocation",
    30 => "features",
    31 => "signature target",
    32 => "embedded signature",
    100 => "internal or user-defined",
    101 => "internal or user-defined",
    102 => "internal or user-defined",
    103 => "internal or user-defined",
    104 => "internal or user-defined",
    105 => "internal or user-defined",
    106 => "internal or user-defined",
    107 => "internal or user-defined",
    108 => "internal or user-defined",
    109 => "internal or user-defined",
    110 => "internal or user-defined",
  }

  def self.typelabel(type)
    TYPES[type]
  end

  TAG_LOADER = {}
  TAG_SCANNER = {}

  T_CRITICAL = 0b0_1000_0000

  def initialize(type = nil)
    @type = type
  end

  def scan(io)
  end

  attr_reader :type

  def type=(type)
    unless TYPES.key?(type)
      raise "Unknown type: #{type}"
    end
    @type = type
  end

  def typelabel
    Packet.typelabel(@type)
  end

  def dump
    body = dump_1octet(@type) + dump_body
    dump_length_new(body.size) + body
  end

  def self.load(port)
    length = load_length_new(port)
    type = load_type(port)
    critical = type & T_CRITICAL
    type &= ~T_CRITICAL
    unless TAG_LOADER.key?(type)
      if critical
        raise "Not supported: #{type}"
      else
        STDERR.puts "Unknown subpacket: #{type}"
      end
    end
    packet = TAG_LOADER[type].call(port, length - 1)
    if packet.type and packet.type != type
      raise "Illegal type"
    end
    packet.type = type
    packet
  end

  def self.scan(port, io = STDOUT)
    length = load_length_new(port)
    type = load_type(port)
    critical = (type & T_CRITICAL).nonzero?
    type &= ~T_CRITICAL
    critlabel = critical ? "Critical" : "Non-critical"
    io.puts "#{critlabel} Sub: #{typelabel(type)}(#{type})(#{length - 1} bytes)\n"
    if !TAG_SCANNER.key?(type) and critical
      raise "Not supported: #{type}"
    end
    io.indent(4) do
      TAG_SCANNER[type].call(io, port, length - 1)
    end
  end

private

  def dump_body
    raise NotImplementedError
  end

  def self.load_type(port)
    load_1octet(port)
  end

  def self.add_loader(tag, method)
    if tag.is_a?(Enumerable)
      tag.each do |tagitem|
        TAG_LOADER[tagitem] = method
      end
    else
      TAG_LOADER[tag] = method
    end
  end

  def self.add_scanner(tag, method)
    if tag.is_a?(Enumerable)
      tag.each do |tagitem|
        TAG_SCANNER[tagitem] = method
      end
    else
      TAG_SCANNER[tag] = method
    end
  end
end


end
end
end
