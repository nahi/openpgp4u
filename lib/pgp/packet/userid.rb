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


require 'pgp/packet/packet'


module PGP
module Packet


class UserID < Packet
  def initialize(userid = nil)
    super(13)
    self.userid = userid
  end

  def scan(io)
    super
    io.puts "User ID: #{@userid}"
  end

  attr_accessor :userid

private

  def dump_body
    @userid
  end

  def self.loader(port, length)
    new(port.read(length))
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(13, method(:loader))
  add_scanner(13, method(:scanner))
end


end
end
