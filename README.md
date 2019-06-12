vts
====

VirusTotal Summary for files

usage
-------

* set VirusTotal apikey to environment variable `VTAPIKEY`
  * exec with `-p` option if you use public apikey.

* input hash list from stdin 
  * 1 hash / line
  * sha256 / sha1 / md5

```sh
$ curl http://www.example.com/something/includes/ioc.html | IoCs hashes |  sort | head -n 5 |  vts --filter-detected --use-public-api -v Microsoft -v CrowdStrike -v Cylance
```

```tsv
resource	sha256	sha1	md5	Microsoft	CrowdStrike	Cylance	positives	total	scan_date	permalink
01e7207e732e67fb3280597ea39bb8ca59fba7bdede1bb4d509e0947d69a5e0a	01e7207e732e67fb3280597ea39bb8ca59fba7bdede1bb4d509e0947d69a5e0a	b4b16ef88bb78cccf06f4d1b7bcecda7fbf5cc0d	906fee48d6feae1aacdddee3893b8a4e	true	NA	NA	32	58	2019-02-25 19:49:11	https://www.virustotal.com/file/01e7207e732e67fb3280597ea39bb8ca59fba7bdede1bb4d509e0947d69a5e0a/analysis/1551124151/
1790952c31d0f142519e8d5762bd441be97cb050b353ecdc91b19a8b44ea59d5	1790952c31d0f142519e8d5762bd441be97cb050b353ecdc91b19a8b44ea59d5	2b382c4cef6ed2d255ab710f5f1ef4f59c2f2c4d	416fa052af17cbb75efdaff82563c5b4	true	NA	NA	32	58	2019-02-25 19:49:14	https://www.virustotal.com/file/1790952c31d0f142519e8d5762bd441be97cb050b353ecdc91b19a8b44ea59d5/analysis/1551124154/
19554594d13500ff0c0f5d73d07fa4ec0bf44ca2b3b2581be470cdd02919a7d0	19554594d13500ff0c0f5d73d07fa4ec0bf44ca2b3b2581be470cdd02919a7d0	57618f342c39f672338ee2f24188dbf523178eb4	52a848b6cab27457375d009db8cea4c9	true	NA	NA	37	59	2019-03-04 17:17:28	https://www.virustotal.com/file/19554594d13500ff0c0f5d73d07fa4ec0bf44ca2b3b2581be470cdd02919a7d0/analysis/1551719848/
204d34b2c3271db299dec30ccf0ca845dcd33558b0ee86eb956db3e2a6b4d5c2	204d34b2c3271db299dec30ccf0ca845dcd33558b0ee86eb956db3e2a6b4d5c2	6c69b526d36944168a906e7ea6e366099f1310fe	849680e299225725e90c4d401fe48170	true	NA	NA	32	54	2019-03-01 03:58:28	https://www.virustotal.com/file/204d34b2c3271db299dec30ccf0ca845dcd33558b0ee86eb956db3e2a6b4d5c2/analysis/1551412708/
2d6a7cc9a14b7d9764bd481abc84a06739e94a9bef7a84c6a30b0c5b65cdf463	2d6a7cc9a14b7d9764bd481abc84a06739e94a9bef7a84c6a30b0c5b65cdf463	271502ec17e30bd4e22729e4802f3928214e8986	ff7784287a7d580b499442d256d32a68	true	NA	NA	32	57	2019-02-25 19:49:25	https://www.virustotal.com/file/2d6a7cc9a14b7d9764bd481abc84a06739e94a9bef7a84c6a30b0c5b65cdf463/analysis/1551124165/
```

### options

```console
$ vts --help
virustotal summary for files
please set VirusTotal apikey to $VTAPIKEY (Private Mass API recommended)

USAGE:
    vts [FLAGS] [OPTIONS]

FLAGS:
    -d, --filter-detected        filter detected files (remove rows not detected on virustotal) this includes -f option.
    -e, --filter-exists          filter exists files (remove rows not exists on virustotal)
    -D, --filter-not-detected    filter not detected files (remove rows detected least one vendor on virustotal) this
                                 includes -f option.
    -E, --filter-not-exists      filter not exists files (remove rows exists on virustotal)
    -h, --help                   Prints help information
    -p, --use-public-api         sleep 15 sec for every request (default 500ms)
    -V, --version                Prints version information
    -H, --without-header         don't show headers

OPTIONS:
    -v, --vendors <vendors>...    vendors to be included in summary
```

Installation
--------------

```sh
cargo install --git https://github.com/0x75960/vts
```
