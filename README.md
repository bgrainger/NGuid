# NGuid

[![Continuous Integration](https://github.com/bgrainger/NGuid/actions/workflows/ci.yaml/badge.svg)](https://github.com/bgrainger/NGuid/actions/workflows/ci.yaml)
![NuGet](https://img.shields.io/nuget/v/NGuid)

## About

NGuid provides efficient creation of name-based GUIDs according to [RFC4122](https://datatracker.ietf.org/doc/html/rfc4122):

* Version 3 - created from an MD5 hash of a name
* Version 5 (default) - created from a SHA1 hash of a name

## Usage

```csharp
// returns a "Version 5" UUID by default: {74738ff5-5367-5958-9aee-98fffdcd1876}
var guid = GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, "www.example.org"u8);

// can also create "Version 3": {0012416f-9eec-3ed4-a8b0-3bceecde1cd9}
var guidv3 = GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, "www.example.org"u8, version: 3);
```

## License

[MIT](https://github.com/bgrainger/NGuid/blob/master/LICENSE)
