use std::collections::HashMap;
use std::env::var as env_var;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use dirs::home_dir;
use regex::Regex;
use rusoto_core::{HttpClient, Region};
use rusoto_credential::{
    AutoRefreshingProvider, AwsCredentials, CredentialsError, ProfileProvider,
    ProvideAwsCredentials,
};
use rusoto_sts::{StsAssumeRoleSessionCredentialsProvider, StsClient};
use tokio::sync::RwLock;

const SOURCE_PROFILE: &str = "source_profile";
const ROLE_ARN: &str = "role_arn";

#[derive(Clone)]
pub struct ConfigAssumeRoleProvider {
    default_region: Region,
    session_name: String,
    sts_assume_role_provider:
        Arc<RwLock<Option<AutoRefreshingProvider<StsAssumeRoleSessionCredentialsProvider>>>>,
}

impl ConfigAssumeRoleProvider {
    pub fn new(default_region: Region, session_name: String) -> Self {
        Self {
            default_region,
            session_name,
            sts_assume_role_provider: Arc::new(RwLock::new(None)),
        }
    }
}

impl Default for ConfigAssumeRoleProvider {
    fn default() -> Self {
        Self {
            default_region: Region::default(),
            session_name: concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"))
                .to_string(),
            sts_assume_role_provider: Arc::new(RwLock::new(None)),
        }
    }
}

#[async_trait::async_trait]
impl ProvideAwsCredentials for ConfigAssumeRoleProvider {
    async fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
        {
            let reader_lock = self.sts_assume_role_provider.read().await;
            if let Some(provider) = &*reader_lock {
                return provider.credentials().await;
            }
        }
        let provider =
            create_assume_role_profile(self.default_region.clone(), self.session_name.clone())?;
        let mut writer_lock = self.sts_assume_role_provider.write().await;
        *writer_lock = Some(provider);
        let reader_lock = writer_lock.downgrade();
        if let Some(provider) = &*reader_lock {
            return provider.credentials().await;
        } else {
            unreachable!()
        }
    }
}

/////////////////////////////////////////
// Code below is inspired and largely copied from https://gist.github.com/tomykaira/9b4b39b91dc750dfd2c7521eac7c4c59
//
// The MIT License (MIT)
//
// Copyright (c) 2017 Rusoto Project Developers
// Copyright (c) 2020 tomykaira
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

fn create_assume_role_profile(
    default_region: Region,
    session_name: String,
) -> Result<AutoRefreshingProvider<StsAssumeRoleSessionCredentialsProvider>, CredentialsError> {
    let config = parse_config_file(default_profile_location()?.as_path())
        .ok_or_else(|| CredentialsError::new("Failed to parse config file"))?;
    let source_profile_name = config
        .get(&default_profile_name())
        .and_then(|props| props.get(SOURCE_PROFILE))
        .map(std::borrow::ToOwned::to_owned)
        .ok_or_else(|| CredentialsError::new("Failed to find source_profile in config file"))?;
    let role_arn = config
        .get(&default_profile_name())
        .and_then(|props| props.get(ROLE_ARN))
        .map(std::borrow::ToOwned::to_owned)
        .ok_or_else(|| CredentialsError::new("Failed to find role_arn in config file"))?;
    let source_profile = ProfileProvider::with_default_credentials(source_profile_name)?;
    let source_profile_region_string = source_profile.region_from_profile().unwrap_or(None);
    let source_profile_region = if let Some(s) = source_profile_region_string {
        Region::from_str(&s).unwrap_or(default_region)
    } else {
        default_region
    };
    let sts = StsClient::new_with(
        HttpClient::new().unwrap(),
        source_profile,
        source_profile_region,
    );
    let provider = StsAssumeRoleSessionCredentialsProvider::new(
        sts,
        role_arn,
        session_name,
        None,
        None,
        None,
        None,
    );
    rusoto_credential::AutoRefreshingProvider::new(provider)
}

/////////////////////////////////////////
// Following definitions are from rusoto.

// Quoted from rusoto-credentials/profile.rs
const AWS_PROFILE: &str = "AWS_PROFILE";
const AWS_SHARED_CREDENTIALS_FILE: &str = "AWS_SHARED_CREDENTIALS_FILE";
const DEFAULT: &str = "default";

// Quoted from rusoto-credentials/profile.rs
fn new_profile_regex() -> Regex {
    Regex::new(r"^\[(profile )?([^\]]+)\]$").expect("Failed to compile regex")
}

// Quoted from rusoto-credentials/profile.rs
fn parse_config_file(file_path: &Path) -> Option<HashMap<String, HashMap<String, String>>> {
    match fs::metadata(file_path) {
        Err(_) => return None,
        Ok(metadata) => {
            if !metadata.is_file() {
                return None;
            }
        }
    };
    let profile_regex = new_profile_regex();
    let file = File::open(file_path).expect("expected file");
    let file_lines = BufReader::new(&file);
    let result: (HashMap<String, HashMap<String, String>>, Option<String>) = file_lines
        .lines()
        .filter_map(|line| {
            line.ok()
                .map(|l| l.trim_matches(' ').to_owned())
                .into_iter()
                .find(|l| !l.starts_with('#') && !l.is_empty())
        })
        .fold(Default::default(), |(mut result, profile), line| {
            if profile_regex.is_match(&line) {
                let caps = profile_regex.captures(&line).unwrap();
                let next_profile = caps.get(2).map(|value| value.as_str().to_string());
                (result, next_profile)
            } else {
                match &line
                    .splitn(2, '=')
                    .map(|value| value.trim_matches(' '))
                    .collect::<Vec<&str>>()[..]
                {
                    [key, value] if !key.is_empty() && !value.is_empty() => {
                        if let Some(current) = profile.clone() {
                            let values = result.entry(current).or_insert_with(HashMap::new);
                            (*values).insert((*key).to_string(), (*value).to_string());
                        }
                        (result, profile)
                    }
                    _ => (result, profile),
                }
            }
        });
    Some(result.0)
}

// Quoted from rusoto-credentials/profile.rs
fn default_profile_location() -> Result<PathBuf, CredentialsError> {
    let env = non_empty_env_var(AWS_SHARED_CREDENTIALS_FILE);
    match env {
        Some(path) => Ok(PathBuf::from(path)),
        None => hardcoded_profile_location(),
    }
}

// Quoted from rusoto-credentials/profile.rs
fn hardcoded_profile_location() -> Result<PathBuf, CredentialsError> {
    match home_dir() {
        Some(mut home_path) => {
            home_path.push(".aws");
            home_path.push("config"); // <<<<<<<<<< NOTE: original value is "credentials", but now "config".
            Ok(home_path)
        }
        None => Err(CredentialsError::new("Failed to determine home directory.")),
    }
}

// Quoted from rusoto-credentials/profile.rs
fn default_profile_name() -> String {
    non_empty_env_var(AWS_PROFILE).unwrap_or_else(|| DEFAULT.to_owned())
}

// Quoted from rusoto-credentials/profile.rs
fn non_empty_env_var(name: &str) -> Option<String> {
    match env_var(name) {
        Ok(value) => {
            if value.is_empty() {
                None
            } else {
                Some(value)
            }
        }
        Err(_) => None,
    }
}
