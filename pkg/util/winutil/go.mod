module github.com/DataDog/datadog-agent/pkg/util/winutil

go 1.16

replace github.com/DataDog/datadog-agent/pkg/util/log => ../log

require (
	github.com/DataDog/datadog-agent/pkg/util/log v0.31.0-rc.8
	github.com/stretchr/testify v1.8.1
	golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f
)
