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


require 'digest/md5'
require 'digest/sha1'


module PGP


module HashAlgorithm
  ALGORITHMS = {
    # MD5: 1.2.840.113549.2.5
    1 => ["MD5", 16, [0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48,
      0x86, 0xF7, 0x0D, 0x02, 0x05,
      0x05, 0x00, 0x04, 0x10]],
    # SHA-1: 1.3.14.3.2.26
    2 => ["SHA-1", 20, [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0E, 0x03,
      0x02, 0x1A,
      0x05, 0x00, 0x04, 0x14]],
    # RIPEMD-160: 1.3.36.3.2.1
    3 => ["RIPEMD-160", 20, [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24,
      0x03, 0x02, 0x01,
      0x05, 0x00, 0x04, 0x14]],
    # SHA256: 2.16.840.1.101.3.4.2.1
    4 => ["Reserved"],
    5 => ["Reserved"],
    6 => ["Reserved"],
    7 => ["Reserved"],
    8 => ["SHA256", 32, [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
      0x05, 0x00, 0x04, 0x20]],
    # SHA384: 2.16.840.1.101.3.4.2.2
    9 => ["SHA384", 48, [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
      0x05, 0x00, 0x04, 0x30]],
    # SHA512:2.16.840.1.101.3.4.2.3
    10 => ["SHA512", 64, [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
      0x05, 0x00, 0x04, 0x40]],
    100 => ["Private/Experimental algorithm"],
    101 => ["Private/Experimental algorithm"],
    102 => ["Private/Experimental algorithm"],
    103 => ["Private/Experimental algorithm"],
    104 => ["Private/Experimental algorithm"],
    105 => ["Private/Experimental algorithm"],
    106 => ["Private/Experimental algorithm"],
    107 => ["Private/Experimental algorithm"],
    108 => ["Private/Experimental algorithm"],
    109 => ["Private/Experimental algorithm"],
    110 => ["Private/Experimental algorithm"],
  }

  def self.include?(algorithm)
    ALGORITHMS.key?(algorithm)
  end

  def self.label(algorithm)
    if data = ALGORITHMS[algorithm]
      data[0]
    else
      raise "Not supported: #{algorithm}"
    end
  end

  def self.dump_summary(algorithm)
    "Hash algorithm - #{label(algorithm)}(#{algorithm})"
  end

  def self.calc(algorithm, data)
    case algorithm
    when 1
      Digest::MD5.digest(data)
    when 2
      Digest::SHA1.digest(data)
    else
      raise "Not supported: #{algorithm}"
    end
  end

  def self.hashlength(algorithm)
    if data = ALGORITHMS[algorithm]
      data[1]
    else
      raise "Not supported: #{algorithm}"
    end
  end

  def self.asnoid(algorithm)
    if data = ALGORITHMS[algorithm]
      data[2] ? data[2].pack("c*") : nil
    else
      nil
    end
  end
end


end
