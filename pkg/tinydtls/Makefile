PKG_NAME=tinydtls
PKG_URL=https://github.com/rfuentess/TinyDTLS.git
# PKG_VERSION=RIOT-OS
PKG_VERSION=b59271d6914e0517c6d8dee5ebdebe1f48752733
PKG_LICENSE=EPL-1.0,EDL-1.0

.PHONY: all

all: git-download
	$(MAKE) -C $(PKG_BUILDDIR)

include $(RIOTBASE)/pkg/pkg.mk
