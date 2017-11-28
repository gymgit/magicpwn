.PHONY: all clean update

all:
	$(MAKE) -C preeny
	$(MAKE) -C dump-seccomp
	cd libc-database && ./get
	cd libseccomp && ./autogen.sh
	cd libseccomp && ./configure
	$(MAKE) -C libseccomp

update: all

clean:
	$(MAKE) -C preeny clean
	$(MAKE) -C dump-seccomp clean
	$(MAKE) -C libseccomp clean
