module PGP


module Util
  def random_bytes(nbytes, nonzero = false)
    require 'openssl'
    bytes = OpenSSL::Random.random_bytes(nbytes)
    if nonzero
      bytes.gsub!(/\0/, '')
      while bytes.length < nbytes
        bytes += OpenSSL::Random.random_bytes(nbytes - bytes.length)
        bytes.gsub!(/\0/, '')
      end
    end
    # ToDo: delete after test
    raise if bytes.length != nbytes
    bytes
  end
  module_function :random_bytes

  def checksum(bytes)
    sum = 0
    bytes.each_byte do |c|
      sum += c
    end
    sum & 0xffff
  end
  module_function :checksum

  CRC24_INIT = 0x00b704ce
  CRC24_POLY = 0x01864cfb
  
  def crc24(src)
    crc = CRC24_INIT
    src.each_byte do |c|
      crc ^= c << 16
      8.times do
        crc <<= 1
        crc ^= CRC24_POLY if (crc & 0x01000000).nonzero?
      end
    end
    crc & 0x00ffffff
  end
  module_function :crc24
end


end
