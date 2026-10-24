using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using NGuid;
using NGuid.NativeAot.Tests;

// exercise every public API in a trimmed, Native AOT-compiled app
var name = "www.example.com";
var nameBytes = Encoding.UTF8.GetBytes(name);

// name-based UUIDs (https://www.rfc-editor.org/rfc/rfc9562#name-example-of-a-uuidv3-value and following)
Check(GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, name), "2ed6657d-e927-568b-95e1-2665a8aea6a2", "CreateFromName(string)");
Check(GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, name, 3), "5df41881-3aed-3515-88a7-2f4a814cf09e", "CreateFromName(string, 3)");
Check(GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, nameBytes), "2ed6657d-e927-568b-95e1-2665a8aea6a2", "CreateFromName(byte[])");
Check(GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, "www.example.com"u8, 3), "5df41881-3aed-3515-88a7-2f4a814cf09e", "CreateFromName(ReadOnlySpan<byte>, 3)");

Check(GuidHelpers.CreateVersion8FromName(HashAlgorithmName.SHA256, GuidHelpers.DnsNamespace, nameBytes), "5c146b14-3c52-8afd-938a-375d0df1fbf6", "CreateVersion8FromName(SHA256)");
Check(GuidHelpers.CreateVersion8FromName(HashAlgorithmName.SHA384, GuidHelpers.DnsNamespace, "www.example.com"u8), "3df00ae4-42a7-8066-88ad-1f925b8b8e54", "CreateVersion8FromName(SHA384)");
Check(GuidHelpers.CreateVersion8FromName(HashAlgorithmName.SHA512, GuidHelpers.DnsNamespace, nameBytes), "94ee4ddb-9f36-8018-9ccf-86a4441691e0", "CreateVersion8FromName(SHA512)");
if (SHA3_256.IsSupported)
	Check(GuidHelpers.CreateVersion8FromName(HashAlgorithmName.SHA3_256, GuidHelpers.DnsNamespace, nameBytes), "fc506eca-a1f4-8315-87c8-c71449dfd324", "CreateVersion8FromName(SHA3-256)");

// time-based UUIDs (https://www.rfc-editor.org/rfc/rfc9562#name-example-of-a-uuidv6-value and following)
var timeProvider = new FixedTimeProvider(DateTimeOffset.Parse("2022-02-22T14:22:22-05:00", CultureInfo.InvariantCulture));
CheckPrefix(GuidHelpers.CreateVersion6(timeProvider), "1ec9414c-232a-6b00", "CreateVersion6(TimeProvider)");
CheckPrefix(GuidHelpers.CreateVersion7(timeProvider), "017f22e2-79b0-7", "CreateVersion7(TimeProvider)");
CheckVersion(GuidHelpers.CreateVersion6(), '6', "CreateVersion6()");
CheckVersion(GuidHelpers.CreateVersion7(), '7', "CreateVersion7()");
Check(GuidHelpers.CreateVersion6FromVersion1(GuidHelpers.DnsNamespace), "1d19dad6-ba7b-6810-80b4-00c04fd430c8", "CreateVersion6FromVersion1");

// custom UUIDs
byte[] bytes = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
Check(GuidHelpers.CreateVersion8(bytes), "00112233-4455-8677-8899-aabbccddeeff", "CreateVersion8(byte[])");
Check(GuidHelpers.CreateVersion8(bytes.AsSpan()), "00112233-4455-8677-8899-aabbccddeeff", "CreateVersion8(ReadOnlySpan<byte>)");

// namespace IDs (https://www.rfc-editor.org/rfc/rfc9562#name-namespace-id-usage-and-allo)
Check(GuidHelpers.UrlNamespace, "6ba7b811-9dad-11d1-80b4-00c04fd430c8", "UrlNamespace");
Check(GuidHelpers.IsoOidNamespace, "6ba7b812-9dad-11d1-80b4-00c04fd430c8", "IsoOidNamespace");
Check(GuidHelpers.X500Namespace, "6ba7b814-9dad-11d1-80b4-00c04fd430c8", "X500Namespace");

// argument validation
CheckThrows<ArgumentOutOfRangeException>(() => GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, name, 4), "CreateFromName(version: 4)");
CheckThrows<ArgumentException>(() => GuidHelpers.CreateVersion8FromName(HashAlgorithmName.MD5, GuidHelpers.DnsNamespace, nameBytes), "CreateVersion8FromName(MD5)");

Console.WriteLine("Success");

static void Check(Guid actual, string expected, string api)
{
	if (actual != new Guid(expected))
		throw new InvalidOperationException($"{api}: expected {expected}; got {actual}");
}

static void CheckPrefix(Guid actual, string expectedPrefix, string api)
{
	if (!actual.ToString("d").StartsWith(expectedPrefix, StringComparison.Ordinal))
		throw new InvalidOperationException($"{api}: expected a UUID starting with {expectedPrefix}; got {actual}");
}

static void CheckVersion(Guid actual, char version, string api)
{
	var value = actual.ToString("d");
	if (value[14] != version || !"89ab".Contains(value[19], StringComparison.Ordinal))
		throw new InvalidOperationException($"{api}: expected a version {version} UUID with the RFC 9562 variant; got {actual}");
}

static void CheckThrows<TException>(Action action, string api)
	where TException : Exception
{
	try
	{
		action();
	}
	catch (TException ex) when (ex.GetType() == typeof(TException))
	{
		return;
	}

	throw new InvalidOperationException($"{api}: expected {typeof(TException).Name}");
}
