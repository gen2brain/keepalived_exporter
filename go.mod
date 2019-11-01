module github.com/gen2brain/keepalived_exporter

require (
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/docker/libnetwork v0.8.0-dev.2.0.20191022201816-571783238bee
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/prometheus/client_golang v1.1.0
	github.com/shirou/gopsutil v2.18.12+incompatible
	github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4 // indirect
	github.com/sirupsen/logrus v1.4.2 // indirect
	github.com/stretchr/testify v1.4.0 // indirect
	github.com/vishvananda/netlink v1.0.0 // indirect
	github.com/vishvananda/netns v0.0.0-20190625233234-7109fa855b0f // indirect
	golang.org/x/sys v0.0.0-20191029155521-f43be2a4598c // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gotest.tools v2.2.0+incompatible // indirect
)

replace github.com/Sirupsen/logrus => github.com/sirupsen/logrus v1.0.5

exclude github.com/Sirupsen/logrus v1.4.2

go 1.13
