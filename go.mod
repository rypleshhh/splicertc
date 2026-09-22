module tcp-dormtun

go 1.22.2

require (
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/tailscale/wireguard-go v0.0.0-20231121184858-cc193a0b3272
	github.com/xtaci/smux v1.5.57
	golang.org/x/sys v0.12.0
)

require (
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/stretchr/testify v1.3.0 // indirect
	golang.org/x/net v0.15.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gopkg.in/Knetic/govaluate.v3 v3.0.0 // indirect
)

replace golang.org/x/sys => github.com/golang/sys v0.12.0

replace golang.org/x/net => github.com/golang/net v0.15.0

replace golang.zx2c4.com/wintun => github.com/fumiama/wintun v0.0.0-20211229152851-8bc97c8034c0
