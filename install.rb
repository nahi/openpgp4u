#!/usr/bin/env ruby

require 'rbconfig'
require 'ftools'

include Config

RUBYLIBDIR = CONFIG["rubylibdir"]
RV = CONFIG["MAJOR"] + "." + CONFIG["MINOR"]
SITELIBDIR = CONFIG["sitedir"] + "/" +  RV 
SRCPATH = File.join(File.dirname($0), 'lib')

def install(from, to)
  to_path = File.catname(from, to)
  unless FileTest.exist?(to_path) and File.compare(from, to_path)
    File.install(from, to_path, 0644, true)
  end
end

def install_dir(*path)
  from_path = File.join(SRCPATH, *path)
  unless FileTest.directory?(from_path)
    raise RuntimeError.new("'#{ from_path }' not found.")
  end
  to_path_sitelib = File.join(SITELIBDIR, *path)
  Dir[File.join(from_path, '*.rb')].each do |name|
    basename = File.basename(name)
    File.mkpath(to_path_sitelib, true)
    install(name, to_path_sitelib)
  end
end

begin
  install_dir('pgp')
  install_dir('pgp', 'packet')
  install_dir('pgp', 'packet', 'sigsubpacket')
  install_dir('pgp', 'packet', 'userattrsubpacket')

  puts "install succeed!"

rescue 
  puts "install failed!"
  puts $!

end
