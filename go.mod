module github.com/getlantern/quicwrapper

go 1.12

require (
	github.com/aristanetworks/goarista v0.0.0-20190712234253-ed1100a1c015 // indirect
	github.com/getlantern/ema v0.0.0-20190620044903-5943d28f40e4
	github.com/getlantern/fdcount v0.0.0-20170105153814-6a6cb5839bc5
	github.com/getlantern/golog v0.0.0-20190809085441-26e09e6dd330
	github.com/getlantern/mockconn v0.0.0-20190708122800-637bd46d8034 // indirect
	github.com/getlantern/mtime v0.0.0-20170117193331-ba114e4a82b0 // indirect
	github.com/getlantern/netx v0.0.0-20190110220209-9912de6f94fd
	github.com/getlantern/ops v0.0.0-20190325191751-d70cb0d6f85f
	github.com/lucas-clemente/quic-go v0.7.1-0.20190207125157-7dc4be2ce994
	github.com/oxtoacart/bpool v0.0.0-20190530202638-03653db5a59c
	github.com/prometheus/client_golang v0.8.0
	github.com/stretchr/testify v1.4.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
)

replace github.com/lucas-clemente/quic-go => github.com/getlantern/quic-go v0.7.1-0.20210430210533-e2bcf9129430
