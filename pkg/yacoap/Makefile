PKG_NAME=yacoap
PKG_URL=https://github.com/Gr3yh0und/YaCoAP
PKG_VERSION=4cdaf3f04232a8f5fee91e26972af54b815edb81
PKG_LICENSE=MIT

.PHONY: all

all: git-download
	"$(MAKE)" -C $(PKG_BUILDDIR)

include $(RIOTBASE)/pkg/pkg.mk
