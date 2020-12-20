require 'json'

$setup = JSON.parse(File.read(__dir__ + '/setup.json'))

def in_array(array, search)
  array.each_with_index do |el, idx|
    return idx if el == search
  end
  return -1
end

def gen_ip_file(filename)
  file = File.open(filename, 'w')

  addrs = `ip route show`
  addrs.each_line do |line|
    next if line.match('wlan') or line.match('linkdown')
    line = line.split(" ")
    if (srci = in_array(line, 'src')) >= 0
      file.puts(line[srci+1])
    end
  end

  file.close()
end

ips_file = "/tmp/srtla_ips"
gen_ip_file(ips_file)
system("#{$setup['srtla_path']}/srtla_send 9000 #{ARGV[2]} #{ARGV[3]} #{ips_file} &")

while true do
  system("#{$setup['belacoder_path']}/belacoder #{ARGV[0]} 127.0.0.1 9000 #{ARGV[1]} #{$setup['belacoder_path']}/br")
  sleep 0.5
end
