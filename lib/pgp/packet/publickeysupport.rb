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
require 'pgp/hashalgorithm'


module PGP
module Packet


# requires: dump_key_material_public
module PublicKeySupport
  def initialize(tag, algorithm = nil)
    super(tag)
    self.algorithm = algorithm if algorithm
    @keycreated = nil
  end

  def scan(io)
    super
    io.puts "Algorithm: #{PKeyAlgorithm.label(@algorithm)}(#{@algorithm})"
    io.puts "Key Created: #{@keycreated}\n"
  end

  def algorithm
    @algorithm
  end

  def algorithm=(algorithm)
    unless PKeyAlgorithm.include?(algorithm)
      raise "Unknown algorithm: #{algorithm}"
    end
    @algorithm = algorithm
  end

  def keycreated
    @keycreated
  end

  def keycreated=(keycreated)
    @keycreated = Time.at(keycreated.to_i)
  end

  def encrypt(plain)
    public_encrypt(plain)
  end

  def decrypt(cipher)
    public_decrypt(cipher)
  end

  def keyfingerprint
    HashAlgorithm.calc(2, as_primarykey.dump)
  end

  def keyid
    keyfingerprint[-8, 8]
  end

private

  def public_encrypt(plain)
    raise NotImplementedError
  end

  def public_decrypt(cipher)
    raise NotImplementedError
  end

  def dump_publickey_body
    dump_version + dump_keygen_time + dump_algorithm +
      dump_key_material_public
  end

  def dump_keygen_time
    dump_time(@keycreated)
  end

  def dump_algorithm
    dump_1octet(@algorithm)
  end

  module ModuleSupport
    ALGORITHM_FACTORY = {}

    def add_key_material_factory_public(algorithm, method)
      ALGORITHM_FACTORY[algorithm] = method
    end

    # length cannot be given; public key part is also embedded in a secret key.
    # ugly.
    def load_publickey_body(packet, port)
      packet.version = load_version(port)
      packet.keycreated = load_time(port)
      algorithm = load_algorithm(port)
      unless ALGORITHM_FACTORY.key?(algorithm)
        raise "Not supported: #{algorithm}"
      end
      packet.algorithm = algorithm
      ALGORITHM_FACTORY[algorithm].call(packet, port)
    end

    def load_algorithm(port)
      load_1octet(port)
    end

    def load_version(port)
      load_1octet(port)
    end
  end
end


end
end
