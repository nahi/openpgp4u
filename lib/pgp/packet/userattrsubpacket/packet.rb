require 'pgp/packet/support'


module PGP
module Packet
module UserAttrSubPacket


class Packet
  include Support
  extend Support::ModuleSupport
  
  TYPES = {
    1 => "Image Attribute",
    100 => "private or experimental use",
    101 => "private or experimental use",
    102 => "private or experimental use",
    103 => "private or experimental use",
    104 => "private or experimental use",
    105 => "private or experimental use",
    106 => "private or experimental use",
    107 => "private or experimental use",
    108 => "private or experimental use",
    109 => "private or experimental use",
    110 => "private or experimental use",
  }

  def self.typelabel(type)
    TYPES[type]
  end

  TAG_LOADER = {}
  TAG_SCANNER = {}

  def initialize(type = nil)
    self.type = type
  end

  def type=(type)
    unless TYPES.key?(type)
      raise "Unknown type: #{type}"
    end
    @type = type
  end

  def typelabel
    Packet.typelabel(@type)
  end

  def scan(io)
  end

  def dump
    body = dump_1octet(@type) + dump_body
    dump_length_new(body.size) + body
  end

  def self.load(port)
    length = load_length_new(port)
    type = load_type(port)
    unless TAG_LOADER.key?(type)
      raise "Not supported: #{type}"
    end
    TAG_LOADER[type].call(port, length - 1)
  end

  def self.scan(port, io)
    length = load_length_new(port)
    type = load_type(port)
    io.puts "Sub: #{typelabel(type)}(#{type})(#{length - 1} bytes)"
    unless TAG_SCANNER.key?(type)
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
