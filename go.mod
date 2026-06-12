module github.com/fivetime/sbw-limiter

go 1.24.5

require (
	github.com/fivetime/sbw-contract v0.0.0
	go.fd.io/govpp v0.12.0
)

require (
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/lunixbochs/struc v0.0.0-20200521075829-a4cb8d33dbbe // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	golang.org/x/sys v0.31.0 // indirect
)

replace github.com/fivetime/sbw-contract => ../sbw-contract
