using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace NGuid.Tests;

public class GuidHelpersTests
{
	[Fact]
	public void SwapByteOrder()
	{
		var guid = new Guid(0x01020304, 0x0506, 0x0708, 9, 10, 11, 12, 13, 14, 15, 16);
		var bytes = guid.ToByteArray();
		Assert.Equal([4, 3, 2, 1, 6, 5, 8, 7, 9, 10, 11, 12, 13, 14, 15, 16], bytes);

		GuidHelpers.SwapByteOrder(bytes);
		Assert.Equal([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], bytes);
	}

	[Theory]
	[InlineData("www.widgets.com", 3, "3d813cbb-47fb-32ba-91df-831e1593ac29" /*, TestDisplayName = "RFC 4122 Appendix B, as updated by http://www.rfc-editor.org/errata_search.php?rfc=4122" */)]
	[InlineData("www.widgets.com", 5, "21f7f8de-8051-5b89-8680-0195ef798b6a" /*, TestDisplayName = "Boost Test Suite https://github.com/boostorg/uuid/blob/2bc0c8e71677f387afdc09bc4f8d609d2c74e80e/test/test_generators.cpp#L85C25-L85C121" */)]
	[InlineData("python.org", 3, "6fa459ea-ee8a-3ca4-894e-db77e160355e" /*, TestDisplayName = "Python implementation (http://docs.python.org/library/uuid.html#uuid-example)" */)]
	[InlineData("python.org", 5, "886313e1-3b8a-5372-9b90-0c9aee199e5d" /*, TestDisplayName = "Python implementation (http://docs.python.org/library/uuid.html#uuid-example)" */)]
	public void CreateGuidFromDnsName(string name, int version, string expected) =>
		Assert.Equal(new Guid(expected), GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, name, version));

	[Theory]
	[InlineData("www.terraform.io", 5, "a5008fae-b28c-5ba5-96cd-82b4c53552d6")] // https://developer.hashicorp.com/terraform/language/functions/uuidv5
	[InlineData("www.example.org", 5, "74738ff5-5367-5958-9aee-98fffdcd1876")] // https://stackoverflow.com/a/5541986/23633
	[InlineData("www.example.com", 3, "5df41881-3aed-3515-88a7-2f4a814cf09e")] // https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-example-of-a-uuidv3-value
	[InlineData("www.example.com", 5, "2ed6657d-e927-568b-95e1-2665a8aea6a2")] // https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-example-of-a-uuidv5-value
	public void CreateGuidFromAsciiDnsName(string name, int version, string expected) =>
		Assert.Equal(new Guid(expected), GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, Encoding.ASCII.GetBytes(name), version));

	[Fact]
	public void CreateNullName()
	{
		var ex = Assert.Throws<ArgumentNullException>(() => GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, default(string)!));
		Assert.Equal("name", ex.ParamName);
	}

	[Fact]
	public void CreateInvalidVersion()
	{
		var ex = Assert.Throws<ArgumentOutOfRangeException>(() => GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, "www.example.com", 4));
		Assert.Equal("version", ex.ParamName);
	}

	[Theory]
	[InlineData("6ba7b810-9dad-11d1-80b4-00c04fd430c8", "1d19dad6-ba7b-6810-80b4-00c04fd430c8")] // DnsNamespace
	[InlineData("6ba7b811-9dad-11d1-80b4-00c04fd430c8", "1d19dad6-ba7b-6811-80b4-00c04fd430c8")] // UrlNamespace
	[InlineData("6ba7b812-9dad-11d1-80b4-00c04fd430c8", "1d19dad6-ba7b-6812-80b4-00c04fd430c8")] // IsoOidNamespace
	public void ConvertV1ToV6(string input, string expected) =>
		Assert.Equal(new Guid(expected), GuidHelpers.CreateVersion6FromVersion1(new Guid(input)));

	[Fact]
	public void CreateV6()
	{
		var start = DateTime.UtcNow;
		var bytes = GuidHelpers.CreateVersion6().ToByteArray();
		var end = DateTime.UtcNow;

		// extract the timestamp from the first eight bytes
		var timeHigh = BinaryPrimitives.ReadUInt32LittleEndian(bytes);
		var timeMid = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(4));
		var timeLow = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(6)) & 0xFFFu;
		var timestamp = (long) ((((ulong) timeHigh) << 28) | ((ulong) timeMid << 12) | timeLow);

		// adjust epoch to Windows NT FILETIME (from get_system_time in https://datatracker.ietf.org/doc/html/rfc4122)
		timestamp -=
			(1000 * 1000 * 10L) // seconds
		   * (60 * 60 * 24L) // days
		   * (17 + 30 + 31 + 365 * 18 + 5L); // # of days

		var extractedDateTime = DateTime.FromFileTimeUtc(timestamp);
		Assert.InRange(extractedDateTime, start, end);
	}

#if NET8_0_OR_GREATER
	[Theory]
	[InlineData("1998-02-04T22:13:53.151183Z", "1d19dad6-ba7b-6816")] // timestamp from the RFC 4122 example; see the date on this draft: https://datatracker.ietf.org/doc/html/draft-leach-uuids-guids-01
	[InlineData("2022-02-22T14:22:22-05:00", "1ec9414c-232a-6b00")] // https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-example-of-a-uuidv6-value
	public void CreateV6FromTimeProvider(string timestamp, string expectedPrefix)
	{
		var timeProvider = new FixedTimeProvider(DateTimeOffset.Parse(timestamp, CultureInfo.InvariantCulture));
		var guid = GuidHelpers.CreateVersion6(timeProvider);
		Assert.StartsWith(expectedPrefix, guid.ToString("d"), StringComparison.Ordinal);
	}
#endif

	[Fact]
	public void CreateV7()
	{
		var start = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
		var bytes = GuidHelpers.CreateVersion7().ToByteArray();
		var end = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

		// extract the timestamp from the first eight bytes
		var timeHigh = BinaryPrimitives.ReadUInt32LittleEndian(bytes);
		var timeLow = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(4));
		var extractedTime = (long) ((((ulong) timeHigh) << 16) | timeLow);
		Assert.InRange(extractedTime, start, end);
	}

#if NET8_0_OR_GREATER
	[Theory]
	[InlineData("2022-02-22T14:22:22-05:00", "017f22e2-79b0-7")] // https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-example-of-a-uuidv7-value
	public void CreateV7FromTimeProvider(string timestamp, string expectedPrefix)
	{
		var timeProvider = new FixedTimeProvider(DateTimeOffset.Parse(timestamp, CultureInfo.InvariantCulture));
		var guid = GuidHelpers.CreateVersion7(timeProvider);
		Assert.StartsWith(expectedPrefix, guid.ToString("d"), StringComparison.Ordinal);
	}
#endif

	[Fact]
	public void ConvertV0ToV6() =>
		Assert.Throws<ArgumentException>(() => GuidHelpers.CreateVersion6FromVersion1(default(Guid)));

	[Fact]
	public void ConvertV4ToV6() =>
		Assert.Throws<ArgumentException>(() => GuidHelpers.CreateVersion6FromVersion1(Guid.NewGuid()));

	[Theory]
	[InlineData(0, false, 0)]
	[InlineData(25, false, 0)]
	[InlineData(26, true, 26)]
	[InlineData(40, true, 26)]
	public void TryFormatUlidChars(int bufferSize, bool expectedSuccess, int expectedCharsWritten)
	{
		var buffer = new char[bufferSize];
		var guid = GuidHelpers.CreateVersion7();
		var success = GuidHelpers.TryFormatUlid(guid, buffer, out var charsWritten);
		Assert.Equal(expectedSuccess, success);
		Assert.Equal(expectedCharsWritten, charsWritten);
	}

	[Theory]
	[InlineData(0, false, 0)]
	[InlineData(25, false, 0)]
	[InlineData(26, true, 26)]
	[InlineData(40, true, 26)]
	public void TryFormatUlidBytes(int bufferSize, bool expectedSuccess, int expectedBytesWritten)
	{
		Span<byte> buffer = stackalloc byte[bufferSize];
		var guid = GuidHelpers.CreateVersion7();
		var success = GuidHelpers.TryFormatUlid(guid, buffer, out var bytesWritten);
		Assert.Equal(expectedSuccess, success);
		Assert.Equal(expectedBytesWritten, bytesWritten);
	}

#if NET8_0_OR_GREATER
	[Theory]
	[InlineData(0L, "0000000000")] // https://github.com/azam/ulidj/blob/a3078e5407bf377cf8e0077c181ea9e2917608f6/src/test/java/io/azam/ulidj/ULIDTest.java#L74
	[InlineData(1L, "0000000001")] // https://github.com/azam/ulidj/blob/a3078e5407bf377cf8e0077c181ea9e2917608f6/src/test/java/io/azam/ulidj/ULIDTest.java#L79
	[InlineData(0xFFL, "000000007Z")] // https://github.com/azam/ulidj/blob/a3078e5407bf377cf8e0077c181ea9e2917608f6/src/test/java/io/azam/ulidj/ULIDTest.java#L92
	[InlineData(0x100L, "0000000080")] // https://github.com/azam/ulidj/blob/a3078e5407bf377cf8e0077c181ea9e2917608f6/src/test/java/io/azam/ulidj/ULIDTest.java#L93
	[InlineData(1469918176385L, "01ARYZ6S41")] // https://github.com/ulid/javascript/blob/a5831206a11636c94d4657b9e1a1354c529ee4e9/test.js#L149-L151
	[InlineData(253402300799999L, "76EZ91ZPZZ")] // https://github.com/RobThree/NUlid/blob/21e9dc80c9891d3f7ac957889ab19819f9180bf0/NUlid.Tests/UlidTests.cs#L187C5-L191
	public void CreateUlidWithSpecifiedTime(long unixTimeMs, string expectedPrefix)
	{
		var timeProvider = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(unixTimeMs));
		var guid = GuidHelpers.CreateVersion7(timeProvider);
		Assert.StartsWith(expectedPrefix, GuidHelpers.ToUlidString(guid), StringComparison.Ordinal);
	}
#endif

	[Theory]
	[InlineData("00112233445566778899AABBCCDDEEFF", "00112233-4455-8677-8899-aabbccddeeff")]
	[InlineData("112233445566778899AABBCCDDEEFF00", "11223344-5566-8788-99aa-bbccddeeff00")]
	[InlineData("00000000000000000000000000000000", "00000000-0000-8000-8000-000000000000")]
	[InlineData("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "ffffffff-ffff-8fff-bfff-ffffffffffff")]
	public void CreateV8(string input, string expected)
	{
#if NET8_0_OR_GREATER
		var bytes = Convert.FromHexString(input);
#else
		var bytes = new byte[input.Length / 2];
		for (var i = 0; i < bytes.Length; i++)
			bytes[i] = byte.Parse(input.Substring(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
#endif
		var guid = GuidHelpers.CreateVersion8(bytes);
		Assert.Equal(new Guid(expected), guid);
	}

	[Fact]
	public void CreateV8FromNull() =>
		Assert.Throws<ArgumentNullException>(() => GuidHelpers.CreateVersion8(default(byte[])!));

	[Fact]
	public void CreateV8FromZeroBytes() =>
		Assert.Throws<ArgumentException>(() => GuidHelpers.CreateVersion8(Array.Empty<byte>()));

	// https://github.com/dotnet/roslyn-analyzers/issues/6686
	private static readonly byte[] s_bytes15 = new byte[15];
	private static readonly byte[] s_bytes32 = new byte[32];

	[Fact]
	public void CreateV8FromFifteenBytes() =>
		Assert.Throws<ArgumentException>(() => GuidHelpers.CreateVersion8(s_bytes15));

	[Fact]
	public void CreateV8FromNewArray() =>
		Assert.Equal(new Guid("00000000-0000-8000-8000-000000000000"), GuidHelpers.CreateVersion8(s_bytes32));

#if NET8_0_OR_GREATER
	[Fact]
	public void CreateV8FromEmptySpan() =>
		Assert.Throws<ArgumentException>(() => GuidHelpers.CreateVersion8([]));

	[Fact]
	public void CreateV8FromShortSpan() =>
		Assert.Throws<ArgumentException>(() => GuidHelpers.CreateVersion8(stackalloc byte[15]));

	[Fact]
	public void CreateV8FromNewSpan() =>
		Assert.Equal(new Guid("00000000-0000-8000-8000-000000000000"), GuidHelpers.CreateVersion8(stackalloc byte[32]));
#endif

	[Theory]
	[InlineData("SHA256", "6ba7b810-9dad-11d1-80b4-00c04fd430c8", "www.example.com", "5c146b14-3c52-8afd-938a-375d0df1fbf6")] // https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-example-of-a-uuidv8-value-n
	public void CreateV8FromName(string algorithmName, string namespaceId, string name, string expected) =>
		Assert.Equal(new Guid(expected), GuidHelpers.CreateVersion8FromName(new(algorithmName), new(namespaceId), Encoding.ASCII.GetBytes(name)));

#if NET8_0_OR_GREATER
	private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
	{
		public override DateTimeOffset GetUtcNow() => utcNow;
	}
#endif
}
