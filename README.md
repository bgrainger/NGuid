# NGuid

[![Continuous Integration](https://github.com/bgrainger/NGuid/actions/workflows/ci.yaml/badge.svg)](https://github.com/bgrainger/NGuid/actions/workflows/ci.yaml)
[![NuGet](https://img.shields.io/nuget/v/NGuid)](https://www.nuget.org/packages/NGuid)

## About

NGuid provides efficient creation of name-based and random GUIDs according to
[RFC 4122](https://datatracker.ietf.org/doc/html/rfc4122)
and the current [revision working draft](https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis):

* Version 3 - created from an MD5 hash of a name
* Version 5 - created from a SHA1 hash of a name
* Version 6 - a field-compatible version of UUIDv1, reordered for improved DB locality
* Version 7 - a time-ordered value based on a Unix timestamp
* Version 8 - an RFC-compatible format for experimental or vendor-specific use cases

## Usage

```csharp
// returns a "Version 5" UUID by default: {74738ff5-5367-5958-9aee-98fffdcd1876}
var guid = GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, "www.example.org"u8);

// can also create "Version 3": {0012416f-9eec-3ed4-a8b0-3bceecde1cd9}
var guidv3 = GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, "www.example.org"u8, version: 3);
```

### ULID Compatibility

Because UUIDv7 and [ULID](https://github.com/ulid/spec) share the same format (48-bit Unix timestamp,
80 bits of random data), any v7 GUID can be converted to a ULID string by using `GuidHelpers.ToUlidString`.

### Experimental

The following APIs are based on the current [working draft](https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis)
and are subject to change:

```csharp
// converts {6ba7b810-9dad-11d1-80b4-00c04fd430c8} to {1d19dad6-ba7b-6810-80b4-00c04fd430c8}
var guidv6 = GuidHelpers.CreateVersion6FromVersion1(GuidHelpers.DnsNamespace);

// creates a v7 GUID using the current time and random data 
var guidv7 = GuidHelpers.CreateVersion7();

// any v7 GUID can be converted to a ULID string
var ulid = GuidHelpers.ToUlidString(guidv7);

// .NET 8 only: specify a TimeProvider to provide the timestamp
var guidv7WithTime = GuidHelpers.CreateVersion7(TimeProvider.System);

// creates a v8 GUID using the specified data
ReadOnlySpan<byte> bytes = GetBytes();
var guidv8 = GuidHelpers.CreateVersion8(bytes);

// creates a name-based v8 GUID using the specified hash algorithm
var guidv8ForName = GuidHelpers.CreateVersion8FromName(HashAlgorithmName.SHA256,
    GuidHelpers.DnsNamespace, "www.example.com"u8);
```

## License

[MIT](https://github.com/bgrainger/NGuid/blob/master/LICENSE)
