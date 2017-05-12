PKG_NAME=yacoap
PKG_URL=https://github.com/Gr3yh0und/YaCoAP
PKG_VERSION=516b4ad3ac1f0b00cd67608e389311782c62a40c
PKG_LICENSE=MIT

.PHONY: all

all: git-download
	"$(MAKE)" -C $(PKG_BUILDDIR)

include $(RIOTBASE)/pkg/pkg.mk
