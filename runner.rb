require 'json'

$setup = JSON.parse(File.read(__dir__ + '/setup.json'))

system("ruby #{$setup['strla_path']}/gen_source_ips.rb > #{$setup['strla_path']}/ips")
system("#{$setup['strla_path']}/srtla_send 9000 #{ARGV[2]} #{ARGV[3]} #{$setup['strla_path']}/ips &")

while true do
  system("#{$setup['belacoder_path']}/belacoder #{ARGV[0]} 127.0.0.1 9000 #{ARGV[1]} #{$setup['belacoder_path']}/br")
  sleep 0.5
end
