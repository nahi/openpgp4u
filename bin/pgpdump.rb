#!/usr/bin/env ruby

require 'pgp/packet'
require 'pp'

PGP::Packet::Packet.scan(ARGF)
