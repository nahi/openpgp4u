require 'pgp/util'


module PGP


class Armor
  TYPES = {
    :MESSAGE => "MESSAGE",
    :PUBLIC_KEY_BLOCK => "PUBLIC KEY BLOCK",
    :PRIVATE_KEY_BLOCK => "PRIVATE KEY BLOCK",
    :SIGNATURE => "SIGNATURE"
  }

  def initialize(src = nil)
    @type = nil
    @header = nil
    @body = nil
    @checksum = nil
    if src
      if (src[0] & 0b0_1000_0000).nonzero?
        self.body = src
      else
        parse(src)
      end
    end
  end

  def type
    @type
  end

  def type=(type)
    type = type.intern if type.respond_to?(:intern)
    unless TYPES.key?(type)
      raise "Unknown type: " + type.to_s
    end
    @type = type
  end

  def header=(header)
    @header = header
  end

  def body
    @body
  end

  def body=(body)
    @body = body
    calc_checksum
  end

  def dump
    check_dump
    dump_header_line + dump_header + dump_blank + dump_body + dump_checksum +
      dump_tail
  end

  def self.parse(src)
    Armor.new(src)
  end

private

  def parse(src)
    status = :header_line
    bodysrc = ""
    src.each do |line|
      line.sub!(/\r?\n\z/, '')
      case status
      when :header_line
        if /^-----BEGIN PGP ([^-]+)-----$/ =~ line
          self.type = $1.gsub(/ /, '_')
          status = :header
        else
          # skip this line
        end
      when :header
        if /^\S*$/ =~ line
          status = :body
        end
      when :body
        if /^=(....)$/ =~ line
          checksum = $1.unpack("m*")[0]
          self.body = bodysrc.unpack("m*")[0]
          if checksum != @checksum
            raise "Illegal checksum: #{@checksum} expected: #{checksum}"
          end
          status = :tail_line
        else
          bodysrc << line
        end
      when :tail_line
        if /^-----END PGP ([^-]+)-----$/ =~ line
          if self.type != ($1.gsub(/ /, '_')).intern
            raise "Illegal tail format definition"
          end
          return        # ignore trailing lines
        else
          raise "Tail line not found"
        end
      else
        raise "Illegal state"
      end
    end
    raise "Parsing failed: not an armor format?"
  end

  def check_dump
    raise "Not initialized" if @type.nil? or @body.nil? or @checksum.nil?
  end

  def dump_header_line
    "-----BEGIN PGP " + TYPES[@type] + "-----\n"
  end

  def dump_header
    @header ? @header.sub(/[\r\n]*\z/, "\n") : ""
  end

  def dump_blank
    "\n"
  end

  def dump_body
    [@body].pack("m50")
  end

  def dump_checksum
    "=" + [@checksum].pack("m*")
  end

  def dump_tail
    "-----END PGP " + TYPES[@type] + "-----\n"
  end

  def calc_checksum
    @checksum = [Util.crc24(@body)].pack("N")[1, 3]
  end
end


end


if __FILE__ == $0
  src = <<EOP
-----BEGIN PGP MESSAGE-----
Version: OpenPrivacy 0.99

yDgBO22WxBHv7O8X7O/jygAEzol56iUKiXmV+XmpCtmpqQUKiQrFqclFqUDBovzS
vBSFjNSiVHsuAA==
=njUN
-----END PGP MESSAGE-----
EOP
  include PGP
  d = Armor.new(src)
  p d
end
