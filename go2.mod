module onechunter

go 1.24.0

require (
  github.com/Azure/go-ntlmssp v0.1.1
  github.com/klauspost/compress v1.18.0
  golang.org/x/crypto v0.45.0
)

require github.com/pierrec/lz4/v4 v4.1.22

replace github.com/Azure/go-ntlmssp => github.com/Azure/go-ntlmssp v0.1.1
replace github.com/klauspost/compress => github.com/klauspost/compress v1.18.0
replace github.com/pierrec/lz4/v4 => github.com/pierrec/lz4/v4 v4.1.22
replace golang.org/x/crypto => github.com/golang/crypto v0.45.0
replace golang.org/x/net => github.com/golang/net v0.47.0
replace golang.org/x/sys => github.com/golang/sys v0.38.0
replace golang.org/x/term => github.com/golang/term v0.37.0
replace golang.org/x/text => github.com/golang/text v0.31.0
