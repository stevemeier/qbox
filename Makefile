UNAME := $(shell uname)

VERSION := $(shell git rev-parse --short HEAD)

GOLDFLAGS += -X main.Version=$(VERSION)
GOFLAGS = -ldflags "$(GOLDFLAGS)"

all:	_goget asncheck badhelo badrcptto bouncelimit checkpassword-client checkpassword-server chpasswd deliver filterservice greylist mfcheck rblcheck rcpt-verify returnpath rwlcheck sessionid spfcheck trust-log
clean:
	rm asncheck badhelo badrcptto bouncelimit checkpassword-client checkpassword-server chpasswd deliver filterservice greylist messageid mfcheck rblcheck rcpt-verify returnpath rwlcheck sessionid spfcheck trust-log
_goget:
	go get blitiri.com.ar/go/spf
	go get github.com/baruwa-enterprise/clamd
	go get github.com/c-robinson/iplib
	go get github.com/davecgh/go-spew/spew
	go get github.com/DavidGamba/go-getoptions
	go get github.com/GehirnInc/crypt
	go get github.com/go-sql-driver/mysql
	go get github.com/gorilla/mux
	go get github.com/hgfischer/go-otp
	go get github.com/jordan-wright/email
	go get github.com/mattn/go-sqlite3
	go get github.com/teamwork/spamc
	go get golang.org/x/net/publicsuffix
	go get golang.org/x/sys/unix
asncheck:
	go build $(GOFLAGS) asncheck.go
	strip asncheck
badhelo:
	gcc -O2 -D_FORTIFY_SOURCE -o badhelo badhelo.c
	strip badhelo
badrcptto:
	go build $(GOFLAGS) badrcptto.go
	strip badrcptto
bouncelimit:
	gcc -O2 -D_FORTIFY_SOURCE -o bouncelimit bouncelimit.c
	strip bouncelimit
checkpassword-client:
	go build $(GOFLAGS) checkpassword-client.go
	strip checkpassword-client
checkpassword-server:
	go build $(GOFLAGS) checkpassword-server.go
ifeq ($(UNAME), Linux)
strip checkpassword-server
endif
chpasswd:
	go build $(GOFLAGS) chpasswd.go
	strip chpasswd
deliver:
	go build $(GOFLAGS) deliver.go
	strip deliver
filterservice:
	go build $(GOFLAGS) filterservice.go
	strip filterservice
greylist:
	go build $(GOFLAGS) greylist.go
	strip greylist
messageid:
	gcc -O2 -D_FORTIFY_SOURCE -luuid -o messageid messageid.c
	strip messageid
mfcheck:
	go build $(GOFLAGS) mfcheck.go
	strip mfcheck
rblcheck:
	gcc -O2 -D_FORTIFY_SOURCE -o rblcheck rblcheck.c
	strip rblcheck
rcpt-verify:
	go build $(GOFLAGS) rcpt-verify.go
	strip rcpt-verify
returnpath:
	gcc -O2 -D_FORTIFY_SOURCE -o returnpath returnpath.c
	strip returnpath
rwlcheck:
	gcc -O2 -D_FORTIFY_SOURCE -o rwlcheck rwlcheck.c
	strip rwlcheck
sessionid:
	gcc -O2 -D_FORTIFY_SOURCE -luuid -o sessionid sessionid.c
	strip sessionid
spfcheck:
	go build $(GOFLAGS) spfcheck.go
	strip spfcheck
trust-log:
	gcc -O2 -D_FORTIFY_SOURCE -o trust-log trust-log.c
	strip trust-log
