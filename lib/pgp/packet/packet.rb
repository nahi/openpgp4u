require 'stringio'
require 'pgp/port'
require 'pgp/indentdumpport'
require 'pgp/armor'
require 'pgp/packet/support'


module PGP
module Packet


class Packet
  include Support
  extend Support::ModuleSupport

  TAGS = {
    0 => "Reserved",
    1 => "Public-Key Encrypted Session Key Packet",
    2 => "Signature Packet",
    3 => "Symmetric-Key Encrypted Session Key Packet",
    4 => "One-Pass Signature Packet",
    5 => "Secret Key Packet",
    6 => "Public Key Packet",
    7 => "Secret Subkey Packet",
    8 => "Compressed Data Packet",
    9 => "Symmetrically Encrypted Data Packet",
    10 => "Marker Packet",
    11 => "Literal Data Packet",
    12 => "Trust Packet",
    13 => "User ID Packet",
    14 => "Public Subkey Packet",
    17 => "User Attribute Packet",
    18 => "Symmetrically Encrypted and MDC Packet",
    19 => "Modification Detection Code Packet",
  }

  def self.taglabel(tag)
    TAGS[tag]
  end

  TAG_LOADER = {}
  TAG_SCANNER = {}

  H_BASE            = 0b0_1000_0000
  H_FORMAT_MASK     = 0b0_0100_0000
  H_OLD_TAG_MASK    = 0b0_0011_1100
  H_OLD_LENGTH_MASK = 0b0_0000_0011
  H_NEW_TAG_MASK    = 0b0_0011_1111

  def initialize(tag)
    unless TAGS[tag]
      raise "Unknown tag: #{tag}"
    end
    @tag = tag
    @version = 4
  end

  def scan(io)
  end

  attr_reader :tag
  attr_accessor :body, :version

  def dump
    check_dump
    body = dump_body
    dump_header(body) + body
  end

  def self.load(port)
    loadport = wrap_port(port)
    packets = []
    while !loadport.eof?
      newheader, tag, lengthdefined = load_header(loadport)
      initpos = loadport.readlength
      unless TAG_LOADER.key?(tag)
        raise "Not supported: #{tag}"
      end
      packet = TAG_LOADER[tag].call(loadport, lengthdefined)
      readlength = loadport.readlength - initpos
      if readlength != lengthdefined
        raise "Parsing failed: #{readlength}/#{lengthdefined}"
      end
      packets << packet
    end
    packets
  end

  def self.scan(port, io = STDOUT)
    if io.is_a?(IndentDumpPort)
      dumpport = io
    else
      dumpport = IndentDumpPort.for(io)
    end
    loadport = wrap_port(port)
    while !loadport.eof?
      newheader, tag, lengthdefined = load_header(loadport)
      newtag = newheader ? "New" : "Old"
      dumpport.puts "#{newtag}: #{taglabel(tag)}(tag #{tag})(#{lengthdefined} bytes)\n"
      initpos = loadport.readlength
      dumpport.indent(4) do
        unless TAG_SCANNER.key?(tag)
          dumpport.puts format("Not supported", 4)
          loadport.read(lengthdefined)    # skip
        else
          TAG_SCANNER[tag].call(dumpport, loadport, lengthdefined)
          readlength = loadport.readlength - initpos
          if readlength != lengthdefined
            raise "Parsing failed: #{readlength}/#{lengthdefined}"
          end
        end
      end
    end
  end

private

  def check_dump
    raise "Not initialized" if @tag.nil?
  end

  def dump_header(body)
    v = H_BASE
    v |= H_FORMAT_MASK & (@newheader ? 1 : 0)
    v |= (@tag << 2) & H_OLD_TAG_MASK
    v |= length_type_old(body.size) & H_OLD_LENGTH_MASK
    dump_1octet(v) + dump_length_old(body.size)
  end

  def dump_body
    raise NotImplementedError
  end

  def self.wrap_port(port)
    unless port.respond_to?(:read)
      port = StringIO.new(port.to_s)
    end
    c = port.read(1)
    if (c[0] & H_BASE).nonzero?
      loadport = Port.for(port)
      loadport.put(c)
    else
      loadport = Port.for(StringIO.new(Armor.new(c + port.read).body))
    end
    loadport
  end

  def self.load_header(port)
    v = load_1octet(port)
    if (H_BASE & v).zero?
      raise "Illegal PGP packet (#{H_BASE} must be always one): #{v}"
    end
    if (H_FORMAT_MASK & v).nonzero?
      tag = H_NEW_TAG_MASK & v
      length = load_length_new(port)
      newheader = true
    else
      tag = (H_OLD_TAG_MASK & v) >> 2
      lengthtype = H_OLD_LENGTH_MASK & v
      length = load_length_old(port, lengthtype)
      newheader = false
    end
    return [newheader, tag, length]
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

  def self.format(str, indent = nil)
    str = trim_eol(str)
    str = trim_indent(str)
    if indent
      str.gsub(/^/, " " * indent)
    else
      str
    end
  end

  def self.trim_eol(str)
    str.collect { |line|
      line.sub(/\r?\n$/, "") + "\n"
    }.join
  end

  def self.trim_indent(str)
    indent = nil
    str = str.collect { |line| untab(line) }.join
    str.each do |line|
      head = line.index(/\S/)
      if !head.nil? and (indent.nil? or head < indent)
        indent = head
      end
    end
    return str unless indent
    str.collect { |line|
      line.sub(/^ {0,#{indent}}/, "")
    }.join
  end

  def self.untab(line, ts = 8)
    while pos = line.index(/\t/)
      line = line.sub(/\t/, " " * (ts - (pos % ts)))
    end
    line
  end
end


end
end
