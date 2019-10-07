all:	asncheck badhelo badrcptto bouncelimit checkpassword-client mfcheck rblcheck rwlcheck spfcheck trust-log
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
heluna:
	go build heluna.go
	strip heluna
mfcheck:
	go build mfcheck.go
	strip mfcheck
rblcheck:
	gcc -O2 -D_FORTIFY_SOURCE -o rblcheck rblcheck.c
	strip rblcheck
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
