setup() {
    load '/usr/lib/bats/bats-support/load'
    load '/usr/lib/bats/bats-assert/load'
}

@test "Ping self" {
    run ./ipxping -c 2 00000001.00dead000101.0000 00000001.00dead000101.9086
    assert_success
    assert_output --partial "from 00000001.00dead000101.9086"
}

@test "Ping ipxrtr (net 1)" {
    run ./ipxping -c 2 00000001.00dead000101.0000 00000001.00dead00010f.9086
    assert_success
    assert_output --partial "from 00000001.00dead00010f.9086"
}

@test "Ping ipxrtr (net 2)" {
    run ./ipxping -c 2 00000001.00dead000101.0000 00000002.00dead00020f.9086
    assert_success
    assert_output --partial "from 00000002.00dead00020f.9086"
}

@test "Ping ipxrtr (net 3)" {
    run ./ipxping -c 2 00000001.00dead000101.0000 00000003.00dead00030f.9086
    assert_success
    assert_output --partial "from 00000003.00dead00030f.9086"
}

@test "Ping ipxhost002" {
    run ./ipxping -c 2 00000001.00dead000101.0000 00000002.00dead000202.9086
    assert_success
    assert_output --partial "from 00000002.00dead000202.9086"
}

@test "Ping ipxhost003" {
    run ./ipxping -c 2 00000001.00dead000101.0000 00000003.00dead000303.9086
    assert_success
    assert_output --partial "from 00000003.00dead000303.9086"
}

@test "Ping broadcast (net 1)" {
    run ./ipxping -c 2 00000001.00dead000101.0000 00000001.ffffffffffff.9086
    assert_success
    refute_output --partial "from 00000001.00dead000101.9086"
    assert_output --partial "from 00000001.00dead00010f.9086"
}

@test "Ping broadcast (net 2)" {
    run ./ipxping -c 2 00000001.00dead000101.0000 00000002.ffffffffffff.9086
    assert_success
    assert_output --partial "from 00000002.00dead000202.9086"
    assert_output --partial "from 00000002.00dead00020f.9086"
}

@test "Ping broadcast (net 3)" {
    run ./ipxping -c 2 00000001.00dead000101.0000 00000003.ffffffffffff.9086
    assert_success
    assert_output --partial "from 00000003.00dead000303.9086"
    assert_output --partial "from 00000003.00dead00030f.9086"
}
