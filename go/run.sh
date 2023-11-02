
test=UserFindLedger
test=UserGetVersion
test='UserGetPublicKey$'
test=UserGetPublicKeyETH
test=UserPK_HDPaths
test=UserSignHash
test='UserSign$'

zemu="-tags ledger_zemu"

go clean -testcache
go test -v ./... $zemu -run $test

