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
  TAG_LOADER = {}

  def initialize(type = nil)
    self.type = type
  end

  def type=(type)
    unless TYPES.key?(type)
      raise "Unknown type: #{type}"
    end
    @type = type
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

private

  def dump_body
    raise NotImplementedError
  end

  def self.load_type(port)
    load_1octet(port)
  end

  def self.add_loader(type, method)
    TAG_LOADER[type] = method
  end

  def self.scanner(port, length)
    loader(port, length).summary
  end
end


end
end
end
