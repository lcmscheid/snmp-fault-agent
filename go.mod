module snmpfault

go 1.24.7

require (
	github.com/gosnmp/gosnmp v1.36.2-0.20231009064202-d306ed5aa998
	github.com/slayercat/GoSNMPServer v0.5.2
)

require (
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/shirou/gopsutil/v3 v3.23.11 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/sirupsen/logrus v1.8.3 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
	golang.org/x/sys v0.15.0 // indirect
)

// GoSNMPServer answers multi-varbind GETNEXT and instance GETBULK
// non-repeaters wrongly (#11, slayercat/GoSNMPServer#19), and refuses a SET
// with readOnly or genErr where RFC 3416 names notWritable and wrongType (#10).
// The fork carries the fixes until upstream releases them; drop this line then.
replace github.com/slayercat/GoSNMPServer => github.com/lcmscheid/GoSNMPServer v0.0.0-20260930193251-bb75b9b4d209
