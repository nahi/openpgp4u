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
    

module HexDump
  # Written by Arai-san and published at [ruby-list:31987].
  # http://blade.nagaokaut.ac.jp/cgi-bin/scat.rb/ruby/ruby-list/31987
  def encode(str)
    offset = 0
    result = []
    while raw = str.slice(offset, 16) and raw.length > 0
      # data field
      data = ''
      for v in raw.unpack('N* a*')
	if v.kind_of? Integer
	  data << sprintf("%08x ", v)
	else
	  v.each_byte {|c| data << sprintf("%02x", c) }
	end
      end
      # text field
      text = raw.tr("\000-\037\177-\377", ".")
      result << sprintf("%08x  %-36s  %s", offset, data, text)
      offset += 16
      # omit duplicate line
      if /^(#{ Regexp.quote(raw) })+/n =~ str[offset .. -1]
	result << sprintf("%08x  ...", offset)
	offset += $&.length
	# should print at the end
	if offset == str.length
	  result << sprintf("%08x  %-36s  %s", offset-16, data, text)
	end
      end
    end
    result
  end
  module_function :encode
end


end
