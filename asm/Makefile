
TEMPLATE_DISASMS = \
  transit-x86_64.disasm \
  transit-i686.disasm \
  transit-aarch64.disasm \

all: ../src/template.inc

../src/template.inc: $(TEMPLATE_DISASMS) template.rb
	ruby template.rb > $@

transit-x86_64.disasm: transit-x86_64.s
	x86_64-linux-gnu-gcc -c $<
	x86_64-linux-gnu-objdump -d $(<:.s=.o) >$@

transit-i686.disasm: transit-i686.s
	i686-linux-gnu-gcc -c $<
	i686-linux-gnu-objdump -d $(<:.s=.o) >$@

transit-aarch64.disasm: transit-aarch64.s
	aarch64-linux-gnu-gcc -c $<
	aarch64-linux-gnu-objdump -d $(<:.s=.o) >$@

clean:
	$(RM) *.o *.disasm
