
def disasm_to_c_code(file)
  File.open(file) do |f|
    puts "#define TRANSIT_CODE_TEMPLATE { \\"
    code_size = 0
    def_lines = []
    f.each do |line|
      case line
      when /^(\h+) <([^>]+)>:/
        addr = $1
        symbol = $2
        if /addr$/ =~ symbol
          def_lines << "#define TRANSIT_#{symbol.upcase} 0x#{code_size.to_s(16)}"
        end
        puts "  /* #{addr} <#{symbol}>: */ \\"
      when /(\s*\h+):\t([^\t]+)(?:\t(.*))?/
        addr = $1
        machine_code = $2
        asm_code = $3
        size = 0
        machine_code = machine_code.gsub(/(\h+) /) do
          code_size += 1
          "0x#{$1},"
        end.strip
        if asm_code
          asm_code = asm_code.tr("\t", ' ')
        else
          asm_code = ''
        end
        puts "  /* #{addr}: */ #{machine_code.ljust(35)} /* #{asm_code} */ \\"
      end
    end
    puts "  }"
    def_lines.each { | line | puts line }
    puts "#define TRANSIT_CODE_SIZE 0x#{code_size.to_s(16)}"
  end
end

puts <<EOS
// -*- c -*-
// Created by asm/template.rb

#if defined(CPU_X86_64)

// x86_64
EOS
disasm_to_c_code('transit-x86_64.disasm')
puts <<EOS

#elif defined(CPU_X86)

// Windows 32-bit and Linux i686
EOS
disasm_to_c_code('transit-i686.disasm')
puts <<EOS

#elif defined(CPU_ARM64)

// ARM64
EOS
disasm_to_c_code('transit-aarch64.disasm')
puts <<EOS

#endif
EOS
