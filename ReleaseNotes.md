# Release Notes

## Pending

* Throw `ArgumentNullException` for a null `byte[]` name; .NET 6+ previously hashed it as an empty name.
* Update `System.Memory` dependency to 4.6.3.
* `CreateVersion8FromName` supports SHA-3 on .NET 8 (previously .NET 9+ only) and no longer accepts MD5 or SHA-1 on .NET 9+.
* `CreateVersion6` sets the multicast bit in its random node ID, as required by RFC 9562.
* `CreateVersion6FromVersion1` rejects GUIDs that don't have the RFC 9562 variant.

## 1.0.0

* Update to RFC 9562. (There are no changes from Version 14 of the RFC draft.)
* Support .NET 9.
* Use `Guid(bytes, bigEndian)` constructor under .NET 8 instead of byte swapping.

## 0.3.0

Update to Version 14 of the RFC draft.

* **Breaking** Remove public `Guid` properties for hash space IDs.
* `GuidHelpers.CreateVersion8FromName` no longer hashes the hash space ID, meaning that it generates a different UUID (than v0.2.0) for the same algorithm, namespace ID, and name.

## 0.2.0

Add the following experimental APIs:

* `GuidHelpers.CreateVersion6`- Creates a new Version 6 UUID based on the current time and a random node ID.
  * On .NET 8, supports a `TimeProvider` to provide the current time.
* `GuidHelpers.CreateVersion7` - Creates a new Version 7 UUID based on the current time and random data.
  * On .NET 8, supports a `TimeProvider` to provide the current time.
* `GuidHelpers.CreateVersion8` - Creates a new Version 8 UUID based on the specified data.
* `GuidHelpers.CreateVersion8FromName` - Creates a new Version 8 UUID based on the specified name and hash algorithm.

## 0.1.0

* First public release.
* Provide `GuidHelpers.CreateFromName` to create Version 3 and Version 5 UUIDs.
