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


class Port
  def self.for(port)
    new(port)
  end

  class << self
    private :new
  end

  def initialize(port)
    @port = port
    @readlength = 0
    @str = ''
  end

  def readlength
    @readlength
  end

  def read(size = nil)
    if size.nil?
      return @str + @port.read
    end
    if @str.empty?
      result = @port.read(size)
    elsif @str.size < size
      result = @str
      result << @port.read(size - @str.size)
      @str = ''
    else
      result = @str[0, size]
      @str = @str[size..-1]
    end
    @readlength += result.size
    if result.size != size
      raise "Input stream corruption: #{result.size}/#{size}"
    end
    result
  end

  def put(str)
    @str << str
    @readlength -= str.size
  end

  def eof?
    @port.eof?
  end
end


end
