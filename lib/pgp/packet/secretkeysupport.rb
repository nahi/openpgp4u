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


require 'pgp/pkeyalgorithm'
require 'pgp/s2kspecifier'
require 'pgp/packet/publickeysupport'
require 'pgp/packet/s2ksupport'


module PGP
module Packet


module SecretKeySupport
  include PublicKeySupport
  include S2KSupport

  def initialize(tag, algorithm = nil)
    super(tag, algorithm)
    @checksum = nil
  end

  attr_accessor :checksum

  def scan(io)
    super
    io.puts "Checksum - #{@checksum.unpack("H*")[0]}" if @checksum
  end

  def encrypt(plain)
    secret_encrypt(plain)
  end

  def decrypt(cipher)
    secret_decrypt(cipher)
  end

private

  def secret_encrypt(plain)
    raise NotImplementedError
  end

  def secret_decrypt(cipher)
    raise NotImplementedError
  end

  def dump_secretkey_body
    dump_publickey_body + dump_s2k + dump_key_material_secret
  end

  def dump_s2k
    dump_1octet(0x00)
  end

  def dump_key_material_secret
    raise "Not supported: #{@algorithm}"
  end

  module ModuleSupport
    include PublicKeySupport::ModuleSupport
    include S2KSupport::ModuleSupport

    ALGORITHM_FACTORY = {}

    def add_key_material_factory_secret(algorithm, method)
      ALGORITHM_FACTORY[algorithm] = method
    end

    def load_secretkey_body(packet, port, length)
      initpos = port.readlength
      load_publickey_body(packet, port)
      s2kid = load_s2k(packet, port)
      if s2kid == 0
        ALGORITHM_FACTORY[packet.algorithm].call(packet, port)
        packet.checksum = load_checksum(s2kid, port)
        if packet.checksum != packet.key_material_secret_checksum
          raise "Illegal private key material checksum"
        end
      else
        load_s2k_data(packet, port, (length - (port.readlength - initpos)))
      end
      packet
    end

    def load_checksum(s2kid, port)
      case s2kid
      when 0, 255
        port.read(2)
      when 254
        port.read(20)
      else
        raise "Unknown s2k identifier: #{s2kid}"
      end
    end

    def load_algorithm(port)
      load_1octet(port)
    end
  end
end


end
end
