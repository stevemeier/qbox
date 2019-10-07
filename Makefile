all:	_goget asncheck badhelo badrcptto bouncelimit checkpassword-client greylist mfcheck rblcheck rcpt-verify rwlcheck sessionid spfcheck trust-log
_goget:
	go get blitiri.com.ar/go/spf
	go get github.com/c-robinson/iplib
	go get github.com/go-sql-driver/mysql
	go get github.com/mattn/go-sqlite3
	go get golang.org/x/net/publicsuffix
	go get golang.org/x/sys/unix
	go get gopkg.in/resty.v1
asncheck:
	go build asncheck.go
	strip asncheck
badhelo:
	gcc -O2 -D_FORTIFY_SOURCE -o badhelo badhelo.c
	strip badhelo
badrcptto:
	go build badrcptto.go
	strip badrcptto
bouncelimit:
	gcc -O2 -D_FORTIFY_SOURCE -o bouncelimit bouncelimit.c
	strip bouncelimit
checkpassword-client:
	go build checkpassword-client.go
	strip checkpassword-client
greylist:
	go build greylist.go
	strip greylist
heluna:
	go build heluna.go
	strip heluna
mfcheck:
	go build mfcheck.go
	strip mfcheck
rblcheck:
	gcc -O2 -D_FORTIFY_SOURCE -o rblcheck rblcheck.c
	strip rblcheck
rcpt-verify:
	go build rcpt-verify.go
	strip rcpt-verify
rwlcheck:
	gcc -O2 -D_FORTIFY_SOURCE -o rwlcheck rwlcheck.c
	strip rwlcheck
sessionid:
	gcc -O2 -D__FORTIFY_SOURCE -luuid -o sessionid sessionid.c
	strip sessionid
spfcheck:
	go build spfcheck.go
	strip spfcheck
trust-log:
	gcc -O2 -D_FORTIFY_SOURCE -o trust-log trust-log.c
	strip trust-log
