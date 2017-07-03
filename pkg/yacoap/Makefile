PKG_NAME=yacoap
PKG_URL=https://github.com/Gr3yh0und/YaCoAP
PKG_VERSION=c8b48a5b4bb5a8fd224c73af6d95d2e0607f49e5
PKG_LICENSE=MIT

.PHONY: all

all: git-download
	"$(MAKE)" -C $(PKG_BUILDDIR)

include $(RIOTBASE)/pkg/pkg.mk
