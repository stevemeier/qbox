UNAME := $(shell uname)

DATE := $(shell date +%Y%m%d)
VERSION := $(shell git rev-parse --short HEAD)

GOLDFLAGS += -X main.Version=$(DATE)_$(VERSION)
GOFLAGS = -ldflags "$(GOLDFLAGS) -s -w"

all:	asncheck badhelo badrcptto bouncelimit checkpassword-client checkpassword-server chpasswd deliver filterservice greylist mfcheck rblcheck rcpt-verify returnpath rwlcheck sessionid spfcheck trust-log
clean:
	rm asncheck badhelo badrcptto bouncelimit checkpassword-client checkpassword-server chpasswd deliver filterservice greylist messageid mfcheck rblcheck rcpt-verify returnpath rwlcheck sessionid spfcheck trust-log
asncheck: FORCE
	go build $(GOFLAGS) asncheck.go
badhelo:
	gcc -O2 -D_FORTIFY_SOURCE -o badhelo badhelo.c
	strip badhelo
badrcptto: FORCE
	go build $(GOFLAGS) badrcptto.go
bouncelimit:
	gcc -O2 -D_FORTIFY_SOURCE -o bouncelimit bouncelimit.c
	strip bouncelimit
checkpassword-client: FORCE
	go build $(GOFLAGS) checkpassword-client.go
checkpassword-server: FORCE
	go build $(GOFLAGS) checkpassword-server.go
chpasswd: FORCE
	go build $(GOFLAGS) chpasswd.go
deliver: FORCE
	go build $(GOFLAGS) deliver.go
filterservice: FORCE
	go build $(GOFLAGS) filterservice.go
greylist: FORCE
	go build $(GOFLAGS) greylist.go
messageid:
	gcc -O2 -D_FORTIFY_SOURCE -luuid -o messageid messageid.c
	strip messageid
mfcheck: FORCE
	go build $(GOFLAGS) mfcheck.go
rblcheck:
	gcc -O2 -D_FORTIFY_SOURCE -o rblcheck rblcheck.c
	strip rblcheck
rcpt-verify: FORCE
	go build $(GOFLAGS) rcpt-verify.go
returnpath:
	gcc -O2 -D_FORTIFY_SOURCE -o returnpath returnpath.c
	strip returnpath
rwlcheck:
	gcc -O2 -D_FORTIFY_SOURCE -o rwlcheck rwlcheck.c
	strip rwlcheck
sessionid:
	# requires libuuid-devel on CentOS 7
	gcc -O2 -D_FORTIFY_SOURCE -luuid -o sessionid sessionid.c
	strip sessionid
spfcheck: FORCE
	go build $(GOFLAGS) spfcheck.go
trust-log:
	gcc -O2 -D_FORTIFY_SOURCE -o trust-log trust-log.c
	strip trust-log

FORCE: ;
