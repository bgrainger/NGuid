using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace NGuid;

/// <summary>
/// Provides helper methods for working with <see cref="Guid"/>.
/// </summary>
public static class GuidHelpers
{
	/// <summary>
	/// Creates a name-based UUID using the algorithm from <a href="https://www.rfc-editor.org/rfc/rfc4122#section-4.3">RFC 4122 §4.3</a>.
	/// </summary>
	/// <param name="namespaceId">The ID of the namespace.</param>
	/// <param name="name">The name (within that namespace). This string will be converted to UTF-8
	/// bytes then hashed to create the UUID. It must not contain unpaired surrogates.</param>
	/// <param name="version">The version number of the UUID to create; this value must be either
	/// 3 (for MD5 hashing) or 5 (for SHA-1 hashing).</param>
	/// <returns>A UUID derived from the namespace and name.</returns>
#if NET6_0_OR_GREATER
	[SkipLocalsInit]
#endif
	public static Guid CreateFromName(Guid namespaceId, string name, int version = 5)
	{
#if NET6_0_OR_GREATER
		ArgumentNullException.ThrowIfNull(name);
#else
		if (name is null)
			throw new ArgumentNullException(nameof(name));
#endif
		ValidateVersion(version);

		// convert the name to a sequence of octets (as defined by the standard or conventions of its namespace) (step 3)
		// ASSUME: UTF-8 encoding is always appropriate
		// (invalid UTF-16 is rejected rather than replaced with U+FFFD so that different names can't produce the same UUID)
#if NET6_0_OR_GREATER
		int nameLength;
		try
		{
			nameLength = s_strictUtf8.GetByteCount(name);
		}
#else
		byte[] nameBytes;
		try
		{
			nameBytes = s_strictUtf8.GetBytes(name);
		}
#endif
		catch (EncoderFallbackException ex)
		{
			throw new ArgumentException("The name cannot be converted to UTF-8.", nameof(name), ex);
		}

#if NET6_0_OR_GREATER
		// encode the name directly into the buffer that will be hashed, after the space for the namespace ID
		Span<byte> buffer = nameLength < 500 ? stackalloc byte[16 + nameLength + 20] : new byte[16 + nameLength + 20];
		s_strictUtf8.GetBytes(name.AsSpan(), buffer[16..^20]);
		return CreateFromNameBuffer(namespaceId, buffer, version);
#else
		return CreateFromName(namespaceId, nameBytes, version);
#endif
	}

	/// <summary>
	/// Creates a name-based UUID using the algorithm from <a href="https://www.rfc-editor.org/rfc/rfc4122#section-4.3">RFC 4122 §4.3</a>.
	/// </summary>
	/// <param name="namespaceId">The ID of the namespace.</param>
	/// <param name="name">The name (within that namespace).</param>
	/// <param name="version">The version number of the UUID to create; this value must be either
	/// 3 (for MD5 hashing) or 5 (for SHA-1 hashing).</param>
	/// <returns>A UUID derived from the namespace and name.</returns>
	public static Guid CreateFromName(Guid namespaceId, byte[] name, int version = 5)
	{
#if NET6_0_OR_GREATER
		ArgumentNullException.ThrowIfNull(name);
		return CreateFromName(namespaceId, name.AsSpan(), version);
#else
		if (name is null)
			throw new ArgumentNullException(nameof(name));
		ValidateVersion(version);

		// convert the namespace UUID to network order (step 3)
		var namespaceBytes = namespaceId.ToByteArray();
		SwapByteOrder(namespaceBytes);

		// compute the hash of the namespace ID concatenated with the name (step 4)
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
#pragma warning disable CA5351 // Do Not Use Broken Cryptographic Algorithms
		var data = namespaceBytes.Concat(name).ToArray();
		byte[] hash;
		using (var algorithm = version == 3 ? (HashAlgorithm) MD5.Create() : SHA1.Create())
			hash = algorithm.ComputeHash(data);
#pragma warning restore CA5351 // Do Not Use Broken Cryptographic Algorithms
#pragma warning restore CA5350 // Do Not Use Weak Cryptographic Algorithms

		// most bytes from the hash are copied straight to the bytes of the new GUID (steps 5-7, 9, 11-12)
		var newGuid = new byte[16];
		Array.Copy(hash, 0, newGuid, 0, 16);

		// set the four most significant bits (bits 12 through 15) of the time_hi_and_version field to the appropriate 4-bit version number from Section 4.1.3 (step 8)
		newGuid[6] = (byte) ((newGuid[6] & 0x0F) | (version << 4));

		// set the two most significant bits (bits 6 and 7) of the clock_seq_hi_and_reserved to zero and one, respectively (step 10)
		newGuid[8] = (byte) ((newGuid[8] & 0x3F) | 0x80);

		// convert the resulting UUID to local byte order (step 13)
		SwapByteOrder(newGuid);
		return new Guid(newGuid);
#endif
	}

	/// <summary>
	/// Creates a name-based UUID using the algorithm from <a href="https://www.rfc-editor.org/rfc/rfc4122#section-4.3">RFC 4122 §4.3</a>.
	/// </summary>
	/// <param name="namespaceId">The ID of the namespace.</param>
	/// <param name="name">The name (within that namespace).</param>
	/// <param name="version">The version number of the UUID to create; this value must be either
	/// 3 (for MD5 hashing) or 5 (for SHA-1 hashing).</param>
	/// <returns>A UUID derived from the namespace and name.</returns>
#if NET6_0_OR_GREATER
	[SkipLocalsInit]
#endif
	public static Guid CreateFromName(Guid namespaceId, ReadOnlySpan<byte> name, int version = 5)
	{
		// see https://github.com/LogosBible/Logos.Utility/blob/master/src/Logos.Utility/GuidUtility.cs and https://faithlife.codes/blog/2011/04/generating_a_deterministic_guid/ for the original version of this code
		ValidateVersion(version);

#if NET6_0_OR_GREATER
		Span<byte> buffer = name.Length < 500 ? stackalloc byte[16 + name.Length + 20] : new byte[16 + name.Length + 20];
		name.CopyTo(buffer[16..]);
		return CreateFromNameBuffer(namespaceId, buffer, version);
#else
		return CreateFromName(namespaceId, name.ToArray(), version);
#endif
	}

#if NET6_0_OR_GREATER
	// Creates a name-based UUID from 'buffer', which holds 16 bytes of space for the namespace ID, then the name, then 20 bytes of space for the hash.
	private static Guid CreateFromNameBuffer(Guid namespaceId, Span<byte> buffer, int version)
	{
		// convert the namespace UUID to network order (step 3)
#if NET8_0_OR_GREATER
		if (!namespaceId.TryWriteBytes(buffer, bigEndian: true, out _))
			throw new InvalidOperationException("Failed to write namespace ID bytes to buffer");
#else
		if (!namespaceId.TryWriteBytes(buffer))
			throw new InvalidOperationException("Failed to write Guid bytes to buffer");
		SwapByteOrder(buffer);
#endif

		// compute the hash of the namespace ID concatenated with the name (step 4)
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
#pragma warning disable CA5351 // Do Not Use Broken Cryptographic Algorithms
		var success = version == 3
			? MD5.TryHashData(buffer[..^20], buffer[^20..], out var bytesWritten)
			: SHA1.TryHashData(buffer[..^20], buffer[^20..], out bytesWritten);
		if (!success || bytesWritten < 16)
			throw new InvalidOperationException("Failed to hash data");
#pragma warning restore CA5351 // Do Not Use Broken Cryptographic Algorithms
#pragma warning restore CA5350 // Do Not Use Weak Cryptographic Algorithms

		// most bytes from the hash are copied straight to the bytes of the new GUID (steps 5-7, 9, 11-12)
		var newGuid = buffer[^20..^4];

		// set the four most significant bits (bits 12 through 15) of the time_hi_and_version field to the appropriate 4-bit version number from Section 4.1.3 (step 8)
		newGuid[6] = (byte) ((newGuid[6] & 0x0F) | (version << 4));

		// set the two most significant bits (bits 6 and 7) of the clock_seq_hi_and_reserved to zero and one, respectively (step 10)
		newGuid[8] = (byte) ((newGuid[8] & 0x3F) | 0x80);

#if NET8_0_OR_GREATER
		return new Guid(newGuid, bigEndian: true);
#else
		// convert the resulting UUID to local byte order (step 13)
		SwapByteOrder(newGuid);
		return new Guid(newGuid);
#endif
	}
#endif

	/// <summary>
	/// Creates a new Version 6 UUID based on the current time and a random node ID.
	/// </summary>
	/// <returns>A new Version 6 UUID based on the current time and a random node ID.</returns>
	/// <remarks>UUIDs are ordered by their timestamp, which has 100-nanosecond precision but is limited by the
	/// resolution of the system clock (as coarse as 1 to 16 milliseconds on .NET Framework). UUIDs created within the
	/// same clock tick, or after the system clock moves backwards, are not guaranteed to sort in the order they were created.</remarks>
	public static Guid CreateVersion6() =>
		CreateVersion6(DateTimeOffset.UtcNow, paramName: null);

#if NET8_0_OR_GREATER
	/// <summary>
	/// Creates a new Version 6 UUID based on the timestamp returned from <paramref name="timeProvider"/> and a random node ID.
	/// </summary>
	/// <param name="timeProvider">A <see cref="TimeProvider"/> that can provide the current UTC time.</param>
	/// <returns>A new Version 6 UUID based on the specified time and a random node ID.</returns>
	/// <remarks>UUIDs are ordered by their 100-nanosecond timestamp. UUIDs created from the same timestamp, or after
	/// <paramref name="timeProvider"/> returns an earlier time, are not guaranteed to sort in the order they were created.</remarks>
	public static Guid CreateVersion6(TimeProvider timeProvider)
	{
		ArgumentNullException.ThrowIfNull(timeProvider);
		return CreateVersion6(timeProvider.GetUtcNow(), nameof(timeProvider));
	}
#endif

	/// <summary>
	/// Creates a new Version 6 UUID from the specified timestamp.
	/// </summary>
	/// <param name="timestamp">The timestamp to be used to fill the <c>time_high</c>, <c>time_mid</c>, and <c>time_low</c> fields of the UUID.</param>
	/// <param name="paramName">The name of the public method's parameter that supplied <paramref name="timestamp"/>, if any.</param>
	/// <returns>A new time-based Version 6 UUID.</returns>
#if NET6_0_OR_GREATER
	[SkipLocalsInit]
#endif
	private static Guid CreateVersion6(DateTimeOffset timestamp, string? paramName)
	{
		// UUID v1 and v6 use a 60-bit timestamp
		var ticks = (timestamp.UtcDateTime - s_gregorianEpoch).Ticks;
		if (ticks is < 0 or >= 1L << 60)
			throw new ArgumentOutOfRangeException(paramName, timestamp, "The timestamp must be between 15 October 1582 and 31 March 5236.");

		// use the timestamp as the first three fields in the UUID
		var timeHigh = (uint) (ticks >> 28);
		var timeMid = (ushort) (ticks >> 12);
		var timeLow = (ushort) ((ticks & 0xFFF) | 0x6000u);

		// "The clock sequence and node bits SHOULD be reset to a pseudo-random value for each new UUIDv6 generated"
#if NET6_0_OR_GREATER
		Span<byte> bytes = stackalloc byte[8];
		RandomNumberGenerator.Fill(bytes);
#else
		var bytes = new byte[8];
		using var rng = RandomNumberGenerator.Create();
		rng.GetBytes(bytes);
#endif

		// "implementations MUST set the least significant bit of the first octet of the Node ID to 1" (RFC 9562 section 6.10)
		return new Guid(timeHigh, timeMid, timeLow,
			(byte) (bytes[0] & 0x3F | 0x80), bytes[1], (byte) (bytes[2] | 0x01), bytes[3],
			bytes[4], bytes[5], bytes[6], bytes[7]);
	}

	/// <summary>
	/// Creates a Version 6 UUID from a Version 1 UUID.
	/// </summary>
	/// <param name="guid">The Version 1 UUID to convert.</param>
	/// <returns>A UUID in Version 6 format, with the timestamp in MSB order.</returns>
#if NET6_0_OR_GREATER
	[SkipLocalsInit]
#endif
	public static Guid CreateVersion6FromVersion1(Guid guid)
	{
#if NET6_0_OR_GREATER
		Span<byte> guidBytes = stackalloc byte[16];
		guid.TryWriteBytes(guidBytes);
#else
		var guidBytes = guid.ToByteArray();
#endif

		// check that the GUID is a version 1 GUID with the RFC 9562 variant
		if ((guidBytes[7] & 0xF0) != 0x10 || (guidBytes[8] & 0xC0) != 0x80)
			throw new ArgumentException("The GUID must be a version 1 GUID.", nameof(guid));

		// turn the bytes into a 60-bit timestamp; note that the bytes retrieved from the GUID are in LSB order
		var timestamp =
			((ulong) (guidBytes[7] & 0x0F)) << 56 |
			((ulong) guidBytes[6]) << 48 |
			((ulong) guidBytes[5]) << 40 |
			((ulong) guidBytes[4]) << 32 |
			((ulong) guidBytes[3]) << 24 |
			((ulong) guidBytes[2]) << 16 |
			((ulong) guidBytes[1]) << 8 |
			guidBytes[0];

		// rearrange into MSB order (with an LSB permutation that the Guid constructor will undo) and set the version to 6
		guidBytes[3] = (byte) (timestamp >> 52);
		guidBytes[2] = (byte) (timestamp >> 44);
		guidBytes[1] = (byte) (timestamp >> 36);
		guidBytes[0] = (byte) (timestamp >> 28);
		guidBytes[5] = (byte) (timestamp >> 20);
		guidBytes[4] = (byte) (timestamp >> 12);
		guidBytes[7] = (byte) (0x60 | ((timestamp >> 8) & 0x0F));
		guidBytes[6] = (byte) timestamp;

		return new Guid(guidBytes);
	}

	/// <summary>
	/// Creates a new Version 7 UUID based on the current time combined with random data.
	/// </summary>
	/// <returns>A new Version 7 UUID based on the current time and random data.</returns>
	/// <remarks>UUIDs are ordered by their millisecond timestamp. UUIDs created within the same millisecond, or after
	/// the system clock moves backwards, are not guaranteed to sort in the order they were created.</remarks>
	public static Guid CreateVersion7() =>
		CreateVersion7(DateTimeOffset.UtcNow, paramName: null);

#if NET8_0_OR_GREATER
	/// <summary>
	/// Creates a new Version 7 UUID based on the timestamp returned from <paramref name="timeProvider"/> combined with random data.
	/// </summary>
	/// <param name="timeProvider">A <see cref="TimeProvider"/> that can provide the current UTC time.</param>
	/// <returns>A new Version 7 UUID based on the specified time and random data.</returns>
	/// <remarks>UUIDs are ordered by their millisecond timestamp. UUIDs created within the same millisecond, or after
	/// <paramref name="timeProvider"/> returns an earlier time, are not guaranteed to sort in the order they were created.</remarks>
	public static Guid CreateVersion7(TimeProvider timeProvider)
	{
		ArgumentNullException.ThrowIfNull(timeProvider);
		return CreateVersion7(timeProvider.GetUtcNow(), nameof(timeProvider));
	}
#endif

	/// <summary>
	/// Creates a new Version 7 UUID from the specified timestamp.
	/// </summary>
	/// <param name="timestamp">The timestamp to be used to fill the <c>unix_ts_ms</c> field of the UUID.</param>
	/// <param name="paramName">The name of the public method's parameter that supplied <paramref name="timestamp"/>, if any.</param>
	/// <returns>A new time-based Version 7 UUID.</returns>
#if NET6_0_OR_GREATER
	[SkipLocalsInit]
#endif
	private static Guid CreateVersion7(DateTimeOffset timestamp, string? paramName)
	{
		var unixMilliseconds = timestamp.ToUnixTimeMilliseconds();
		if (unixMilliseconds < 0)
			throw new ArgumentOutOfRangeException(paramName, timestamp, "The timestamp must be after 1 January 1970.");

		// "UUIDv7 values are created by allocating a Unix timestamp in milliseconds in the most significant 48 bits ..."
		var timeHigh = (uint) (unixMilliseconds >> 16);
		var timeLow = (ushort) unixMilliseconds;

		// "... and filling the remaining 74 bits, excluding the required version and variant bits, with random bits"
#if NET6_0_OR_GREATER
		Span<byte> bytes = stackalloc byte[10];
		RandomNumberGenerator.Fill(bytes);
#else
		var bytes = new byte[10];
		using var rng = RandomNumberGenerator.Create();
		rng.GetBytes(bytes);
#endif

		var randA = (ushort) (0x7000u | ((bytes[0] & 0xF) << 8) | bytes[1]);

		return new Guid(timeHigh, timeLow, randA,
			(byte) (bytes[2] & 0x3F | 0x80), bytes[3], bytes[4], bytes[5],
			bytes[6], bytes[7], bytes[8], bytes[9]);
	}

	/// <summary>
	/// Creates a Version 8 UUID from the first 16 bytes of the specified input. Those bytes are copied to the returned
	/// <see cref="Guid"/> except for the reserved <c>version</c> and <c>variant</c> bits, which are set to 8
	/// and 2 respectively; any additional bytes are ignored.
	/// </summary>
	/// <param name="bytes">The bytes to use to initialize the UUID.</param>
	/// <returns>A new Version 8 UUID.</returns>
	/// <remarks>This method treats the bytes in big-endian (network) order; the first byte in <paramref name="bytes"/>
	/// will be the first byte in the standard string representation of the returned <see cref="Guid"/>.
	/// This differs from the <see cref="Guid(byte[])"/> constructor, which treats the first three fields as little-endian,
	/// so <see cref="Guid.ToByteArray()"/> returns each of the first three groups of bytes (4, 2, and 2 bytes) in reverse
	/// order compared to <paramref name="bytes"/>; the last 8 bytes are unchanged.
	/// </remarks>
	public static Guid CreateVersion8(byte[] bytes)
	{
#if NET6_0_OR_GREATER
		ArgumentNullException.ThrowIfNull(bytes);
		return CreateVersion8(bytes.AsSpan());
#else
		if (bytes is null)
			throw new ArgumentNullException(nameof(bytes));
		if (bytes.Length < 16)
			throw new ArgumentException("At least sixteen bytes must be provided", nameof(bytes));

		// make a copy of the bytes
		var guidBytes = new byte[16];
		bytes.AsSpan(0, 16).CopyTo(guidBytes);

		// convert the bytes from network order to local byte order (so that bytes[0] is the first byte in the serialized GUID output)
		SwapByteOrder(guidBytes);

		// set the version and variant fields (in local byte order, the version is in byte 7)
		guidBytes[7] = (byte) (0x80 | (guidBytes[7] & 0xF));
		guidBytes[8] = (byte) (0x80 | (guidBytes[8] & 0x3F));

		return new Guid(guidBytes);
#endif
	}

	/// <summary>
	/// Creates a Version 8 UUID from the first 16 bytes of the specified input. Those bytes are copied to the returned
	/// <see cref="Guid"/> except for the reserved <c>version</c> and <c>variant</c> bits, which are set to 8
	/// and 2 respectively; any additional bytes are ignored.
	/// </summary>
	/// <param name="bytes">The bytes to use to initialize the UUID.</param>
	/// <returns>A new Version 8 UUID.</returns>
	/// <remarks>This method treats the bytes in big-endian (network) order; the first byte in <paramref name="bytes"/>
	/// will be the first byte in the standard string representation of the returned <see cref="Guid"/>.
	/// This differs from the <see cref="Guid(byte[])"/> constructor, which treats the first three fields as little-endian,
	/// so <see cref="Guid.ToByteArray()"/> returns each of the first three groups of bytes (4, 2, and 2 bytes) in reverse
	/// order compared to <paramref name="bytes"/>; the last 8 bytes are unchanged.
	/// </remarks>
#if NET6_0_OR_GREATER
	[SkipLocalsInit]
#endif
	public static Guid CreateVersion8(ReadOnlySpan<byte> bytes)
	{
		if (bytes.Length < 16)
			throw new ArgumentException("At least sixteen bytes must be provided", nameof(bytes));

#if NET6_0_OR_GREATER
		// make a copy of the bytes
		Span<byte> guidBytes = stackalloc byte[16];
		bytes[..16].CopyTo(guidBytes);

		// set the version and variant fields
		guidBytes[6] = (byte) (0x80 | (guidBytes[6] & 0xF));
		guidBytes[8] = (byte) (0x80 | (guidBytes[8] & 0x3F));

#if NET8_0_OR_GREATER
		return new Guid(guidBytes, bigEndian: true);
#else
		// convert the bytes from network order to local byte order (so that bytes[0] is the first byte in the serialized GUID output)
		SwapByteOrder(guidBytes);
		return new Guid(guidBytes);
#endif
#else
		return CreateVersion8(bytes.Slice(0, 16).ToArray());
#endif
	}

	/// <summary>
	/// Creates a Version 8 UUID from a name in the specified namespace using the specified hash algorithm, according to the algorithm
	/// in <a href="https://www.rfc-editor.org/rfc/rfc9562#name-name-based-uuid-generation">RFC 9562, section 6.5</a>.
	/// </summary>
	/// <param name="hashAlgorithmName">The name of the hash algorithm to use. Supported values are <c>SHA256</c>, <c>SHA384</c>, and <c>SHA512</c>;
	/// on .NET 8 and later, <c>SHA3-256</c>, <c>SHA3-384</c>, and <c>SHA3-512</c> are also supported if the platform supports SHA-3.</param>
	/// <param name="namespaceId">The namespace ID.</param>
	/// <param name="name">The name within that namespace ID.</param>
	/// <returns>A version 8 UUID formed by hashing the namespace ID and name.</returns>
	public static Guid CreateVersion8FromName(HashAlgorithmName hashAlgorithmName, Guid namespaceId, byte[] name)
	{
#if NET6_0_OR_GREATER
		ArgumentNullException.ThrowIfNull(name);
		return CreateVersion8FromName(hashAlgorithmName, namespaceId, name.AsSpan());
#else
		if (name is null)
			throw new ArgumentNullException(nameof(name));
		using var algorithm = GetHashAlgorithm(hashAlgorithmName);

		// add the namespace bytes (in network order) to the hash
		var namespaceBytes = namespaceId.ToByteArray();
		SwapByteOrder(namespaceBytes);
		algorithm.TransformBlock(namespaceBytes, 0, namespaceBytes.Length, null, 0);

		// add the name to the hash
		algorithm.TransformFinalBlock(name, 0, name.Length);

		// the initial bytes from the hash are copied straight to the bytes of the new GUID
		var newGuid = new byte[16];
		Array.Copy(algorithm.Hash, newGuid, 16);

		// set the version and variant bits
		newGuid[6] = (byte) ((newGuid[6] & 0x0F) | 0x80);
		newGuid[8] = (byte) ((newGuid[8] & 0x3F) | 0x80);

		// convert the resulting UUID to local byte order
		SwapByteOrder(newGuid);
		return new Guid(newGuid);
#endif
	}

	/// <summary>
	/// Creates a Version 8 UUID from a name in the specified namespace using the specified hash algorithm, according to the algorithm
	/// in <a href="https://www.rfc-editor.org/rfc/rfc9562#name-name-based-uuid-generation">RFC 9562, section 6.5</a>.
	/// </summary>
	/// <param name="hashAlgorithmName">The name of the hash algorithm to use. Supported values are <c>SHA256</c>, <c>SHA384</c>, and <c>SHA512</c>;
	/// on .NET 8 and later, <c>SHA3-256</c>, <c>SHA3-384</c>, and <c>SHA3-512</c> are also supported if the platform supports SHA-3.</param>
	/// <param name="namespaceId">The namespace ID.</param>
	/// <param name="name">The name within that namespace ID.</param>
	/// <returns>A version 8 UUID formed by hashing the namespace ID and name.</returns>
#if NET6_0_OR_GREATER
	[SkipLocalsInit]
#endif
	public static Guid CreateVersion8FromName(HashAlgorithmName hashAlgorithmName, Guid namespaceId, ReadOnlySpan<byte> name)
	{
#if NET6_0_OR_GREATER
		HashData hashData = hashAlgorithmName.Name switch
		{
			"SHA256" => SHA256.HashData,
			"SHA384" => SHA384.HashData,
			"SHA512" => SHA512.HashData,
#if NET8_0_OR_GREATER
			"SHA3-256" => SHA3_256.HashData,
			"SHA3-384" => SHA3_384.HashData,
			"SHA3-512" => SHA3_512.HashData,
#endif
			_ => throw new ArgumentException($"Unsupported hash algorithm name: {hashAlgorithmName.Name}", nameof(hashAlgorithmName)),
		};

		Span<byte> buffer = name.Length < 500 ? stackalloc byte[16 + name.Length] : new byte[16 + name.Length];

#if NET8_0_OR_GREATER
		if (!namespaceId.TryWriteBytes(buffer, bigEndian: true, out _))
			throw new InvalidOperationException("Failed to write namespace ID bytes to buffer");
#else
		// convert the namespace UUID to network order
		if (!namespaceId.TryWriteBytes(buffer))
			throw new InvalidOperationException("Failed to write namespace ID bytes to buffer");
		SwapByteOrder(buffer);
#endif

		// compute the hash of [ namespace ID, name ]
		name.CopyTo(buffer[16..]);
		Span<byte> hashOutput = stackalloc byte[64];
		hashData(buffer, hashOutput);

		// the initial bytes from the hash are copied straight to the bytes of the new GUID
		var newGuid = hashOutput[..16];

		// set the version and variant bits
		newGuid[6] = (byte) ((newGuid[6] & 0x0F) | 0x80);
		newGuid[8] = (byte) ((newGuid[8] & 0x3F) | 0x80);

#if NET8_0_OR_GREATER
		return new Guid(newGuid, bigEndian: true);
#else
		// convert the resulting UUID to local byte order
		SwapByteOrder(newGuid);
		return new Guid(newGuid);
#endif
#else
		return CreateVersion8FromName(hashAlgorithmName, namespaceId, name.ToArray());
#endif
	}

#if NET6_0_OR_GREATER
	private delegate int HashData(ReadOnlySpan<byte> source, Span<byte> destination);
#else
	private static HashAlgorithm GetHashAlgorithm(HashAlgorithmName hashAlgorithmName) =>
		hashAlgorithmName.Name switch
		{
			"SHA256" => SHA256.Create(),
			"SHA384" => SHA384.Create(),
			"SHA512" => SHA512.Create(),
			_ => throw new ArgumentException($"Unsupported hash algorithm name: {hashAlgorithmName.Name}", nameof(hashAlgorithmName)),
		};
#endif

	/// <summary>
	/// The namespace for fully-qualified domain names (from RFC 4122, Appendix C).
	/// </summary>
	public static readonly Guid DnsNamespace = new("6ba7b810-9dad-11d1-80b4-00c04fd430c8");

	/// <summary>
	/// The namespace for URLs (from RFC 4122, Appendix C).
	/// </summary>
	public static readonly Guid UrlNamespace = new("6ba7b811-9dad-11d1-80b4-00c04fd430c8");

	/// <summary>
	/// The namespace for ISO OIDs (from RFC 4122, Appendix C).
	/// </summary>
	public static readonly Guid IsoOidNamespace = new("6ba7b812-9dad-11d1-80b4-00c04fd430c8");

	private static void ValidateVersion(int version)
	{
		if (version is not (3 or 5))
			throw new ArgumentOutOfRangeException(nameof(version), version, "version must be either 3 or 5.");
	}

#if !NET8_0_OR_GREATER
	// Converts a GUID (expressed as a byte array) to/from network order (MSB-first).
	internal static void SwapByteOrder(Span<byte> guid)
	{
		(guid[0], guid[3]) = (guid[3], guid[0]);
		(guid[1], guid[2]) = (guid[2], guid[1]);
		(guid[4], guid[5]) = (guid[5], guid[4]);
		(guid[6], guid[7]) = (guid[7], guid[6]);
	}
#endif

	// UUID v1 and v6 uses a count of 100-nanosecond intervals since 00:00:00.00 UTC, 15 October 1582
	private static readonly DateTime s_gregorianEpoch = new(1582, 10, 15, 0, 0, 0, DateTimeKind.Utc);

	// throws EncoderFallbackException for invalid UTF-16 instead of substituting U+FFFD
	private static readonly UTF8Encoding s_strictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
}
