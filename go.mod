module tcp-dormtun

go 1.22.2

require (
	github.com/getlantern/systray v1.2.2
	github.com/tailscale/wireguard-go v0.0.0-20231121184858-cc193a0b3272
	github.com/xtaci/smux v1.5.57
	golang.org/x/sys v0.12.0
)

require (
	github.com/getlantern/context v0.0.0-20190109183933-c447772a6520 // indirect
	github.com/getlantern/errors v0.0.0-20190325191628-abdb3e3e36f7 // indirect
	github.com/getlantern/golog v0.0.0-20190830074920-4ef2e798c2d7 // indirect
	github.com/getlantern/hex v0.0.0-20190417191902-c6586a6fe0b7 // indirect
	github.com/getlantern/hidden v0.0.0-20190325191715-f02dbb02be55 // indirect
	github.com/getlantern/ops v0.0.0-20190325191751-d70cb0d6f85f // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/oxtoacart/bpool v0.0.0-20190530202638-03653db5a59c // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	golang.org/x/net v0.15.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace golang.org/x/sys => github.com/golang/sys v0.12.0

replace golang.org/x/net => github.com/golang/net v0.15.0

replace golang.zx2c4.com/wintun => github.com/fumiama/wintun v0.0.0-20211229152851-8bc97c8034c0
