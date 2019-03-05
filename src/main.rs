use serde::Deserialize;
use std::collections::HashMap;
use std::io::BufRead;
use structopt::StructOpt;

type GenericResult<T> = Result<T, Box<dyn std::error::Error>>;

/// VirusTotalClient for inquiring the file reputations
struct VirusTotalClient {
    apikey: String,
}

/// ScanResult item of "scans"
#[derive(Deserialize, Debug)]
struct ScanResult {
    detected: bool,
    version: Option<String>,
    result: Option<String>,
    update: Option<String>,
}

/// FileReport structure without all_info option.
#[derive(Deserialize, Debug)]
struct RawFileReport {
    response_code: u32,
    verbose_msg: String,
    sha1: Option<String>,
    sha256: Option<String>,
    md5: Option<String>,
    scan_date: Option<String>,
    permalink: Option<String>,
    positives: Option<u32>,
    total: Option<u32>,
    scans: Option<HashMap<String, ScanResult>>,
}

/// FileReport essence in response
#[derive(Debug)]
struct FileReport {
    sha1: String,
    sha256: String,
    md5: String,
    scan_date: String,
    permalink: String,
    positives: u32,
    total: u32,
    scans: HashMap<String, ScanResult>,
}

impl FileReport {
    fn summary(&self, vendors: &Vec<String>) -> String {
        let vendor_result = vendors
            .iter()
            .map(|x| match self.scans.get(x) {
                Some(x) => format!("{}", x.detected),
                None => String::from("NA"),
            })
            .collect::<Vec<String>>()
            .join("\t");
        format!(
            "{}\t{}\t{}\t{}{}\t{}\t{}\t{}",
            self.sha256,
            self.sha1,
            self.md5,
            match vendors.len() {
                0 => String::new(),
                _ => format!("{}\t", vendor_result),
            },
            self.positives,
            self.total,
            self.scan_date,
            self.permalink
        )
    }
}

impl Default for FileReport {
    fn default() -> Self {
        FileReport {
            sha1: String::from("NA"),
            sha256: String::from("NA"),
            md5: String::from("NA"),
            scan_date: String::from("NA"),
            permalink: String::from("NA"),
            positives: 0,
            total: 0,
            scans: HashMap::new(),
        }
    }
}

impl RawFileReport {
    /// export essence with validation
    fn export(self) -> GenericResult<FileReport> {
        if self.response_code != 1 {
            // virustotal returns reposnse code 1 when succeeded to retrieve scan result.
            return Err(format!(
                "VirusTotal returns reponse_code: {}: {}",
                self.response_code, self.verbose_msg,
            )
            .into());
        }

        Ok(FileReport {
            sha1: self.sha1.ok_or(String::from("sha1 is empty"))?,
            sha256: self.sha256.ok_or(String::from("sha256 is empty"))?,
            md5: self.md5.ok_or(String::from("md5 is empty"))?,
            scan_date: self.scan_date.ok_or(String::from("scan_date is empty"))?,
            permalink: self.permalink.ok_or(String::from("permalink is empty"))?,
            positives: self.positives.ok_or(String::from("positives is empty"))?,
            total: self.total.ok_or(String::from("total is empty"))?,
            scans: self.scans.ok_or(String::from("scans is empty"))?,
        })
    }
}

impl VirusTotalClient {
    /// new client from virustotal apikey
    fn new(apikey: &impl AsRef<str>) -> VirusTotalClient {
        VirusTotalClient {
            apikey: String::from(apikey.as_ref()),
        }
    }

    /// get raw file report from virustotal
    fn get_raw_file_report(&self, resource: &impl AsRef<str>) -> GenericResult<RawFileReport> {
        reqwest::get(
            format!(
                "https://www.virustotal.com/vtapi/v2/file/report?apikey={}&resource={}",
                self.apikey,
                resource.as_ref()
            )
            .as_str(),
        )?
        .json()
        .map_err(|e| e.into())
    }

    /// get file report from virustotal
    fn get_file_report(&self, resource: &impl AsRef<str>) -> GenericResult<FileReport> {
        self.get_raw_file_report(resource)?.export()
    }
}

/// virustotal summary for files
/// please set VirusTotal apikey to $VTAPIKEY (Private Mass API recommended)
#[derive(StructOpt, Debug)]
#[structopt(name = "vts")]
struct Opt {
    /// vendors to be included in summary
    #[structopt(short = "v", long = "vendors")]
    vendors: Vec<String>,

    /// don't show headers
    #[structopt(short = "H", long = "without-header")]
    without_header: bool,

    /// sleep 15 sec for every request (default 500ms)
    #[structopt(short = "p", long = "use-public-api")]
    public_api: bool,
}

fn main() -> GenericResult<()> {
    let opt = Opt::from_args();
    let apikey = std::env::var("VTAPIKEY").expect("set virustotal apikey to envvar: $VTAPIKEY");
    let client = VirusTotalClient::new(&apikey);

    if opt.without_header == false {
        println!(
            "resource\tsha1\tsha256\tmd5\t{}positives\ttotal\tscan_date\tpermalink",
            match opt.vendors.len() {
                0 => String::new(),
                _ => format!("{}\t", opt.vendors.join("\t")),
            }
        );
    }

    let stdin = std::io::stdin();
    for l in stdin.lock().lines() {
        let line = l.unwrap();
        let report = match client.get_file_report(&line) {
            Ok(x) => x,
            Err(_) => FileReport::default(),
        };
        println!("{}\t{}", line, report.summary(&opt.vendors));

        if opt.public_api {
            std::thread::sleep(std::time::Duration::from_secs(15));
        } else {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    Ok(())
}
