# Release Notes

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
