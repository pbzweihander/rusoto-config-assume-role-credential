# rusoto-config-assume-role-credential

Rusoto credential provider that reads config file and assumes role specified by `role_arn` field using profile specified by `source_profile`.

```rust
let client = rusoto_logs::CloudWatchLogsClient::new_with(
    rusoto_core::request::HttpClient::new().unwrap(),
    rusoto_config_assume_role_credential::ConfigAssumeRoleProvider::default(),
    Default::default(),
)
```

## License

Major part of this code is from [tomykaira's gist](https://gist.github.com/tomykaira/9b4b39b91dc750dfd2c7521eac7c4c59#file-credentials-rs) and rusoto, which is licensed by MIT License.

_rusoto-config-assume-role-credential_ is licensed under the terms of [MIT License](https://spdx.org/licenses/MIT.html).
