GOMOBILE=gomobile
GOBIND=$(GOMOBILE) bind
BUILDDIR=$(shell pwd)/build
ARTIFACT=$(BUILDDIR)/tun2socks.aar
LDFLAGS='-s -w'
IMPORT_PATH=github.com/eycorsican/go-tun2socks-android
TUN2SOCKS_PATH=$(GOPATH)/src/github.com/eycorsican/go-tun2socks

BUILD_CMD="cd $(BUILDDIR) && $(GOBIND) -a -ldflags $(LDFLAGS) -target=android -o $(ARTIFACT) $(IMPORT_PATH)"

all: $(ARTIFACT)

$(ARTIFACT):
	mkdir -p $(BUILDDIR)
	cd $(TUN2SOCKS_PATH) && make copy
	eval $(BUILD_CMD)
	cd $(TUN2SOCKS_PATH) && make clean

clean:
	rm -rf $(BUILDDIR)
	cd $(TUN2SOCKS_PATH) && make clean
