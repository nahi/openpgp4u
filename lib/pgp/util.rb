# Copyright 2004  NAKAMURA, Hiroshi <nakahiro@sarion.co.jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


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
