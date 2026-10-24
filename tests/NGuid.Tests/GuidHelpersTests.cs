using System.Buffers.Binary;
using System.Security.Cryptography;
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

#if !NET8_0_OR_GREATER
		GuidHelpers.SwapByteOrder(bytes);
		Assert.Equal([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], bytes);
#endif
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
	[InlineData("www.example.com", 3, "5df41881-3aed-3515-88a7-2f4a814cf09e")] // https://www.rfc-editor.org/rfc/rfc9562#name-example-of-a-uuidv3-value
	[InlineData("www.example.com", 5, "2ed6657d-e927-568b-95e1-2665a8aea6a2")] // https://www.rfc-editor.org/rfc/rfc9562#name-example-of-a-uuidv5-value
	public void CreateGuidFromAsciiDnsName(string name, int version, string expected) =>
		Assert.Equal(new Guid(expected), GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, Encoding.ASCII.GetBytes(name), version));

	[Theory]
	[InlineData('a', 499, 5, "fe28ecad-d700-53fa-8e37-d9ec8e9d58c7")]
	[InlineData('a', 500, 5, "23d604e2-7664-5f66-afd0-33691bed5b76")]
	[InlineData('a', 600, 3, "2c7ed2e9-cb86-36a3-91ee-ed34af08b949")]
	[InlineData('a', 600, 5, "3ac74f5b-7542-5321-9815-1c5246f96e15")]
	[InlineData('é', 300, 5, "da50c6e4-b4bf-5a5a-8c35-cbda4ab06c5d")] // 600 bytes of UTF-8
	public void CreateGuidFromLongName(char ch, int count, int version, string expected)
	{
		var name = new string(ch, count);
		Assert.Equal(new Guid(expected), GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, name, version));
		Assert.Equal(new Guid(expected), GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, Encoding.UTF8.GetBytes(name), version));
	}

	[Fact]
	public void CreateNullName()
	{
		var ex = Assert.Throws<ArgumentNullException>(() => GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, default(string)!));
		Assert.Equal("name", ex.ParamName);
	}

	[Fact]
	public void CreateNullNameBytes()
	{
		var ex = Assert.Throws<ArgumentNullException>(() => GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, default(byte[])!));
		Assert.Equal("name", ex.ParamName);
	}

	[Fact]
	public void CreateFromNameWithSurrogatePair() =>
		Assert.Equal(new Guid("52096f1e-2b44-5520-929f-9e587f0f4899"), GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, "\U0001F600"));

	[Fact]
	public void CreateFromNameWithUnpairedSurrogate()
	{
		foreach (var name in new[] { "\uD800", "a\uDFFFb", "\uDC00\uD800" })
		{
			var ex = Assert.Throws<ArgumentException>(() => GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, name));
			Assert.Equal("name", ex.ParamName);
			Assert.IsType<EncoderFallbackException>(ex.InnerException);
		}
	}

	[Fact]
	public void CreateInvalidVersion()
	{
		var ex = Assert.Throws<ArgumentOutOfRangeException>(() => GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, "www.example.com", 4));
		Assert.Equal("version", ex.ParamName);
	}

	[Fact]
	public void CreateInvalidVersionChecksVersionBeforeName()
	{
		// the version is validated before the name is encoded
		var ex = Assert.Throws<ArgumentOutOfRangeException>(() => GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, "\uD800", 4));
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

		// adjust epoch to Windows NT FILETIME (from get_system_time in https://www.rfc-editor.org/rfc/rfc4122)
		timestamp -=
			(1000 * 1000 * 10L) // seconds
		   * (60 * 60 * 24L) // days
		   * (17 + 30 + 31 + 365 * 18 + 5L); // # of days

		var extractedDateTime = DateTime.FromFileTimeUtc(timestamp);
		Assert.InRange(extractedDateTime, start, end);
	}

	[Fact]
	public void CreateV6SetsMulticastBit()
	{
		// the node ID is random, so check enough UUIDs that a missing bit can't go unnoticed by chance
		for (var i = 0; i < 100; i++)
			Assert.Equal(1, GuidHelpers.CreateVersion6().ToByteArray()[10] & 0x01);
	}

#if NET8_0_OR_GREATER
	[Theory]
	[InlineData("1998-02-04T22:13:53.151183Z", "1d19dad6-ba7b-6816")] // timestamp from the RFC 4122 example; see the date on this draft: https://datatracker.ietf.org/doc/html/draft-leach-uuids-guids-01
	[InlineData("2022-02-22T14:22:22-05:00", "1ec9414c-232a-6b00")] // https://www.rfc-editor.org/rfc/rfc9562#name-example-of-a-uuidv6-value
	public void CreateV6FromTimeProvider(string timestamp, string expectedPrefix)
	{
		var timeProvider = new FixedTimeProvider(DateTimeOffset.Parse(timestamp, System.Globalization.CultureInfo.InvariantCulture));
		var guid = GuidHelpers.CreateVersion6(timeProvider);
		Assert.StartsWith(expectedPrefix, guid.ToString("d"), StringComparison.Ordinal);
	}

	[Fact]
	public void CreateV6FromLastValidTimestamp()
	{
		// the last timestamp that fits in 60 bits
		var timeProvider = new FixedTimeProvider(s_gregorianEpoch.AddTicks((1L << 60) - 1));
		Assert.StartsWith("ffffffff-ffff-6fff-", GuidHelpers.CreateVersion6(timeProvider).ToString("d"), StringComparison.Ordinal);
	}

	[Theory]
	[InlineData(-1L)]
	[InlineData(1L << 60)]
	public void CreateV6FromOutOfRangeTimestamp(long ticksSinceGregorianEpoch)
	{
		var timeProvider = new FixedTimeProvider(s_gregorianEpoch.AddTicks(ticksSinceGregorianEpoch));
		var ex = Assert.Throws<ArgumentOutOfRangeException>(() => GuidHelpers.CreateVersion6(timeProvider));
		Assert.Equal("timeProvider", ex.ParamName);
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
	[InlineData("2022-02-22T14:22:22-05:00", "017f22e2-79b0-7")] // https://www.rfc-editor.org/rfc/rfc9562#name-example-of-a-uuidv7-value
	public void CreateV7FromTimeProvider(string timestamp, string expectedPrefix)
	{
		var timeProvider = new FixedTimeProvider(DateTimeOffset.Parse(timestamp, System.Globalization.CultureInfo.InvariantCulture));
		var guid = GuidHelpers.CreateVersion7(timeProvider);
		Assert.StartsWith(expectedPrefix, guid.ToString("d"), StringComparison.Ordinal);
	}

	[Fact]
	public void CreateV7FromTimestampBeforeUnixEpoch()
	{
		var timeProvider = new FixedTimeProvider(DateTimeOffset.UnixEpoch.AddMilliseconds(-1));
		var ex = Assert.Throws<ArgumentOutOfRangeException>(() => GuidHelpers.CreateVersion7(timeProvider));
		Assert.Equal("timeProvider", ex.ParamName);
	}
#endif

	[Fact]
	public void ConvertV0ToV6() =>
		Assert.Throws<ArgumentException>(() => GuidHelpers.CreateVersion6FromVersion1(default(Guid)));

	[Fact]
	public void ConvertV4ToV6() =>
		Assert.Throws<ArgumentException>(() => GuidHelpers.CreateVersion6FromVersion1(Guid.NewGuid()));

	[Theory]
	[InlineData("6ba7b810-9dad-11d1-00b4-00c04fd430c8")] // NCS variant
	[InlineData("6ba7b810-9dad-11d1-c0b4-00c04fd430c8")] // Microsoft variant
	[InlineData("6ba7b810-9dad-11d1-e0b4-00c04fd430c8")] // reserved variant
	public void ConvertNonRfcVariantV1ToV6(string input) =>
		Assert.Throws<ArgumentException>(() => GuidHelpers.CreateVersion6FromVersion1(new Guid(input)));

	[Theory]
	[InlineData("00112233445566778899AABBCCDDEEFF", "00112233-4455-8677-8899-aabbccddeeff")]
	[InlineData("112233445566778899AABBCCDDEEFF00", "11223344-5566-8788-99aa-bbccddeeff00")]
	[InlineData("00000000000000000000000000000000", "00000000-0000-8000-8000-000000000000")]
	[InlineData("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "ffffffff-ffff-8fff-bfff-ffffffffffff")]
	public void CreateV8(string input, string expected)
	{
#if NET5_0_OR_GREATER
		var bytes = Convert.FromHexString(input);
#else
		var bytes = new byte[input.Length / 2];
		for (var i = 0; i < bytes.Length; i++)
			bytes[i] = byte.Parse(input.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);
#endif
		var guid = GuidHelpers.CreateVersion8(bytes);
		Assert.Equal(new Guid(expected), guid);
	}

	[Fact]
	public void CreateV8FromNull() =>
		Assert.Throws<ArgumentNullException>(() => GuidHelpers.CreateVersion8(default(byte[])!));

	[Fact]
	public void CreateV8FromZeroBytes() =>
		Assert.Throws<ArgumentException>(() => GuidHelpers.CreateVersion8([]));

	// https://github.com/dotnet/roslyn-analyzers/issues/6686
	private static readonly byte[] s_bytes15 = new byte[15];
	private static readonly byte[] s_bytes32 = new byte[32];

	[Fact]
	public void CreateV8FromFifteenBytes() =>
		Assert.Throws<ArgumentException>(() => GuidHelpers.CreateVersion8(s_bytes15));

	[Fact]
	public void CreateV8FromNewArray() =>
		Assert.Equal(new Guid("00000000-0000-8000-8000-000000000000"), GuidHelpers.CreateVersion8(s_bytes32));

	[Fact]
	public void CreateV8FromEmptySpan() =>
		Assert.Throws<ArgumentException>(() => GuidHelpers.CreateVersion8([]));

	[Fact]
	public void CreateV8FromShortSpan() =>
		Assert.Throws<ArgumentException>(() => GuidHelpers.CreateVersion8(stackalloc byte[15]));

	[Fact]
	public void CreateV8FromNewSpan() =>
		Assert.Equal(new Guid("00000000-0000-8000-8000-000000000000"), GuidHelpers.CreateVersion8(stackalloc byte[32]));

	[Fact]
	public void CreateV8FromSpan() =>
		Assert.Equal(new Guid("00112233-4455-8677-8899-aabbccddeeff"), GuidHelpers.CreateVersion8([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));

	[Theory]
	[InlineData("SHA256", "6ba7b810-9dad-11d1-80b4-00c04fd430c8", "www.example.com", "5c146b14-3c52-8afd-938a-375d0df1fbf6")] // https://www.rfc-editor.org/rfc/rfc9562#name-example-of-a-uuidv8-value-n
	[InlineData("SHA384", "6ba7b810-9dad-11d1-80b4-00c04fd430c8", "www.example.com", "3df00ae4-42a7-8066-88ad-1f925b8b8e54")]
	[InlineData("SHA512", "6ba7b810-9dad-11d1-80b4-00c04fd430c8", "www.example.com", "94ee4ddb-9f36-8018-9ccf-86a4441691e0")]
	public void CreateV8FromName(string algorithmName, string namespaceId, string name, string expected) =>
		Assert.Equal(new Guid(expected), GuidHelpers.CreateVersion8FromName(new(algorithmName), new(namespaceId), Encoding.ASCII.GetBytes(name)));

#if NET8_0_OR_GREATER
	[Theory]
	[InlineData("SHA3-256", "fc506eca-a1f4-8315-87c8-c71449dfd324")]
	[InlineData("SHA3-384", "ab4f9412-4e4c-87a5-be26-dc72f9adf6ed")]
	[InlineData("SHA3-512", "83120d41-2935-8110-964c-6bd77c735fbc")]
	public void CreateV8FromNameWithSha3(string algorithmName, string expected)
	{
		var isSupported = algorithmName switch
		{
			"SHA3-256" => SHA3_256.IsSupported,
			"SHA3-384" => SHA3_384.IsSupported,
			_ => SHA3_512.IsSupported,
		};
		var name = Encoding.ASCII.GetBytes("www.example.com");
		if (isSupported)
			Assert.Equal(new Guid(expected), GuidHelpers.CreateVersion8FromName(new(algorithmName), GuidHelpers.DnsNamespace, name));
		else
			Assert.Throws<PlatformNotSupportedException>(() => GuidHelpers.CreateVersion8FromName(new(algorithmName), GuidHelpers.DnsNamespace, name));
	}
#endif

	[Theory]
	[InlineData("MD5")]
	[InlineData("SHA1")]
	[InlineData("sha256")]
	[InlineData("")]
#if !NET8_0_OR_GREATER
	[InlineData("SHA3-256")]
#endif
	public void CreateV8FromNameWithUnsupportedAlgorithm(string algorithmName)
	{
		var ex = Assert.Throws<ArgumentException>(() => GuidHelpers.CreateVersion8FromName(new(algorithmName), GuidHelpers.DnsNamespace, Encoding.ASCII.GetBytes("www.example.com")));
		Assert.Equal("hashAlgorithmName", ex.ParamName);
	}

	[Fact]
	public void CreateFromUtf8Name()
	{
		Assert.Equal(new Guid("2ed6657d-e927-568b-95e1-2665a8aea6a2"), GuidHelpers.CreateFromName(GuidHelpers.DnsNamespace, "www.example.com"u8));
		Assert.Equal(new Guid("5c146b14-3c52-8afd-938a-375d0df1fbf6"), GuidHelpers.CreateVersion8FromName(HashAlgorithmName.SHA256, GuidHelpers.DnsNamespace, "www.example.com"u8));
	}

	[Fact]
	public void CreateV8FromNullName()
	{
		var ex = Assert.Throws<ArgumentNullException>(() => GuidHelpers.CreateVersion8FromName(new("SHA256"), GuidHelpers.DnsNamespace, default(byte[])!));
		Assert.Equal("name", ex.ParamName);
	}

#if NET8_0_OR_GREATER
	private static readonly DateTimeOffset s_gregorianEpoch = new(1582, 10, 15, 0, 0, 0, TimeSpan.Zero);

	private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
	{
		public override DateTimeOffset GetUtcNow() => utcNow;
	}
#endif
}
