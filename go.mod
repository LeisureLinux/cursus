module github.com/LeisureLinux/cursus

go 1.26.6

replace github.com/X-VPN/Talaria => ./third_party/talaria

require (
	github.com/X-VPN/Talaria v0.0.0-00010101000000-000000000000
	github.com/things-go/go-socks5 v0.1.1
	golang.org/x/sys v0.45.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/exp v0.0.0-20260529124908-c761662dc8c9 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	gvisor.dev/gvisor v0.0.0-20260122175437-89a5d21be8f0 // indirect
)
