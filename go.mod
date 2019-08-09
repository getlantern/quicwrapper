module github.com/getlantern/quicwrapper

go 1.12

require (
	github.com/aristanetworks/goarista v0.0.0-20190712234253-ed1100a1c015 // indirect
	github.com/getlantern/context v0.0.0-20190109183933-c447772a6520 // indirect
	github.com/getlantern/ema v0.0.0-20190620044903-5943d28f40e4
	github.com/getlantern/errors v0.0.0-20190325191628-abdb3e3e36f7 // indirect
	github.com/getlantern/fdcount v0.0.0-20170105153814-6a6cb5839bc5
	github.com/getlantern/golog v0.0.0-20170508214112-cca714f7feb5
	github.com/getlantern/hex v0.0.0-20190417191902-c6586a6fe0b7 // indirect
	github.com/getlantern/hidden v0.0.0-20190325191715-f02dbb02be55 // indirect
	github.com/getlantern/mockconn v0.0.0-20190708122800-637bd46d8034 // indirect
	github.com/getlantern/mtime v0.0.0-20170117193331-ba114e4a82b0 // indirect
	github.com/getlantern/netx v0.0.0-20190110220209-9912de6f94fd
	github.com/getlantern/ops v0.0.0-20190325191751-d70cb0d6f85f
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/lucas-clemente/quic-go v0.0.0-00010101000000-000000000000
	github.com/oxtoacart/bpool v0.0.0-20190530202638-03653db5a59c // indirect
	github.com/stretchr/testify v1.3.0
	golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2
	golang.org/x/sync v0.0.0-20190423024810-112230192c58
)

replace github.com/lucas-clemente/quic-go => github.com/getlantern/quic-go v0.7.1-0.20190818104938-28e3ca4262e1

replace github.com/marten-seemann/qtls => github.com/marten-seemann/qtls-deprecated v0.0.0-20190207043627-591c71538704
