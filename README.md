vts
====

VirusTotal Summary for files

usage
-------

* input hash list from stdin 
  * 1 hash / line
  * sha256 / sha1 / md5

```sh
$ curl http://example.com | IoCs hashes | vts -v Microsoft -v McAfee > result.tsv
```

### options

```
$ vts --help
virustotal summary for files
please set VirusTotal apikey to $VTAPIKEY (Private Mass API recommended)

USAGE:
    vts [FLAGS] [OPTIONS]

FLAGS:
    -h, --help              Prints help information
    -p, --use-public-api    sleep 15 sec for every request (default 500ms)
    -V, --version           Prints version information
    -H, --without-header    don't show headers

OPTIONS:
    -v, --vendors <vendors>...    vendors to be included in summary
```

Installation
--------------

```sh
cargo install --git https://github.com/0x75960/vts
```
