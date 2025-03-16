all:
	odin build dig

test:
	odin test tests -all-packages
	@rm tests.bin

clean:
	rm tests.bin dig.bin

.PHONY: all clean test
