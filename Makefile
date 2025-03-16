all:
	odin build src/dig

test:
	odin test tests -all-packages
	@rm -f tests.bin

clean:
	rm -f tests.bin dig

.PHONY: all clean test
