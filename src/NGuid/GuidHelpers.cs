using System;
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
	/// Creates a name-based UUID using the algorithm from <a href="https://datatracker.ietf.org/doc/html/rfc4122#section-4.3">RFC 4122 §4.3</a>.
	/// </summary>
	/// <param name="namespaceId">The ID of the namespace.</param>
	/// <param name="name">The name (within that namespace). This string will be converted to UTF-8
	/// bytes then hashed to create the UUID.</param>
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

		// convert the name to a sequence of octets (as defined by the standard or conventions of its namespace) (step 3)
		// ASSUME: UTF-8 encoding is always appropriate
#if NET6_0_OR_GREATER
		Span<byte> nameBytes = name.Length < 500 ? stackalloc byte[name.Length * 3] : new byte[name.Length * 3];
		nameBytes = nameBytes[..Encoding.UTF8.GetBytes(name.AsSpan(), nameBytes)];
		return CreateFromName(namespaceId, nameBytes, version);
#else
		var nameBytes = Encoding.UTF8.GetBytes(name);
		return CreateFromName(namespaceId, nameBytes, version);
#endif
	}

	/// <summary>
	/// Creates a name-based UUID using the algorithm from <a href="https://datatracker.ietf.org/doc/html/rfc4122#section-4.3">RFC 4122 §4.3</a>.
	/// </summary>
	/// <param name="namespaceId">The ID of the namespace.</param>
	/// <param name="name">The name (within that namespace).</param>
	/// <param name="version">The version number of the UUID to create; this value must be either
	/// 3 (for MD5 hashing) or 5 (for SHA-1 hashing).</param>
	/// <returns>A UUID derived from the namespace and name.</returns>
	public static Guid CreateFromName(Guid namespaceId, byte[] name, int version = 5)
	{
#if NET6_0_OR_GREATER
		return CreateFromName(namespaceId, name.AsSpan(), version);
#else
		if (version is not (3 or 5))
			throw new ArgumentOutOfRangeException(nameof(version), version, "version must be either 3 or 5.");

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

#if NET6_0_OR_GREATER
	/// <summary>
	/// Creates a name-based UUID using the algorithm from <a href="https://datatracker.ietf.org/doc/html/rfc4122#section-4.3">RFC 4122 §4.3</a>.
	/// </summary>
	/// <param name="namespaceId">The ID of the namespace.</param>
	/// <param name="name">The name (within that namespace).</param>
	/// <param name="version">The version number of the UUID to create; this value must be either
	/// 3 (for MD5 hashing) or 5 (for SHA-1 hashing).</param>
	/// <returns>A UUID derived from the namespace and name.</returns>
	[SkipLocalsInit]
	public static Guid CreateFromName(Guid namespaceId, ReadOnlySpan<byte> name, int version = 5)
	{
		// see https://github.com/LogosBible/Logos.Utility/blob/master/src/Logos.Utility/GuidUtility.cs and https://faithlife.codes/blog/2011/04/generating_a_deterministic_guid/ for the original version of this code
		if (version is not (3 or 5))
			throw new ArgumentOutOfRangeException(nameof(version), version, "version must be either 3 or 5.");

		// convert the namespace UUID to network order (step 3)
		Span<byte> buffer = name.Length < 500 ? stackalloc byte[16 + name.Length + 20] : new byte[16 + name.Length + 20];
		if (!namespaceId.TryWriteBytes(buffer))
			throw new InvalidOperationException("Failed to write Guid bytes to buffer");
		SwapByteOrder(buffer);

		// compute the hash of the namespace ID concatenated with the name (step 4)
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
#pragma warning disable CA5351 // Do Not Use Broken Cryptographic Algorithms
		name.CopyTo(buffer[16..]);
		var success = version == 3 ?
			MD5.TryHashData(buffer[..^20], buffer[^20..], out var bytesWritten) :
			SHA1.TryHashData(buffer[..^20], buffer[^20..], out bytesWritten);
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

		// convert the resulting UUID to local byte order (step 13)
		SwapByteOrder(newGuid);
		return new Guid(newGuid);
	}
#endif

	/// <summary>
	/// Creates a new Version 6 UUID based on the current time and a random node ID.
	/// </summary>
	/// <returns>A new Version 6 UUID based on the current time and a random node ID.</returns>
	/// <remarks>This method is based on <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-uuid-version-6">draft-ietf-uuidrev-rfc4122bis-14</a> and is subject to change.</remarks>
	public static Guid CreateVersion6() =>
		CreateVersion6(DateTimeOffset.UtcNow);

#if NET8_0_OR_GREATER
	/// <summary>
	/// Creates a new Version 6 UUID based on the timestamp returned from <paramref name="timeProvider"/> and a random node ID.
	/// </summary>
	/// <param name="timeProvider">A <see cref="TimeProvider"/> that can provide the current UTC time.</param>
	/// <returns>A new Version 6 UUID based on the specified time and a random node ID.</returns>
	/// <remarks>This method is based on <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-uuid-version-6">draft-ietf-uuidrev-rfc4122bis-14</a> and is subject to change.</remarks>
	public static Guid CreateVersion6(TimeProvider timeProvider)
	{
		ArgumentNullException.ThrowIfNull(timeProvider);
		return CreateVersion6(timeProvider.GetUtcNow());
	}
#endif

	/// <summary>
	/// Creates a new Version 6 UUID from the specified timestamp.
	/// </summary>
	/// <param name="timestamp">The timestamp to be used to fill the <c>time_high</c>, <c>time_mid</c>, and <c>time_low</c> fields of the UUID.</param>
	/// <returns>A new time-based Version 6 UUID.</returns>
	/// <remarks>This method is based on <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-uuid-version-6">draft-ietf-uuidrev-rfc4122bis-14</a> and is subject to change.</remarks>
#if NET6_0_OR_GREATER
	[SkipLocalsInit]
#endif
	private static Guid CreateVersion6(DateTimeOffset timestamp)
	{
		var ticks = (timestamp.UtcDateTime - s_gregorianEpoch).Ticks;
		if (ticks < 0)
			throw new ArgumentOutOfRangeException(nameof(timestamp), timestamp, "The timestamp must be after 15 October 1582.");

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

		return new Guid(timeHigh, timeMid, timeLow,
			(byte) (bytes[0] & 0x3F | 0x80), bytes[1], bytes[2], bytes[3],
			bytes[4], bytes[5], bytes[6], bytes[7]);
	}

	/// <summary>
	/// Creates a Version 6 UUID from a Version 1 UUID.
	/// </summary>
	/// <param name="guid">The Version 1 UUID to convert.</param>
	/// <returns>A UUID in Version 6 format, with the timestamp in MSB order.</returns>
	/// <remarks>This method is based on <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-uuid-version-6">draft-ietf-uuidrev-rfc4122bis-14</a> and is subject to change.</remarks>
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

		// check that the GUID is a version 1 GUID
		if ((guidBytes[7] & 0xF0) != 0x10)
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
	/// <remarks>This method is based on <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-uuid-version-7">draft-ietf-uuidrev-rfc4122bis-14</a> and is subject to change.</remarks>
	public static Guid CreateVersion7() =>
		CreateVersion7(DateTimeOffset.UtcNow);

#if NET8_0_OR_GREATER
	/// <summary>
	/// Creates a new Version 7 UUID based on the timestamp returned from <paramref name="timeProvider"/> combined with random data.
	/// </summary>
	/// <param name="timeProvider">A <see cref="TimeProvider"/> that can provide the current UTC time.</param>
	/// <returns>A new Version 7 UUID based on the specified time and random data.</returns>
	/// <remarks>This method is based on <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-uuid-version-7">draft-ietf-uuidrev-rfc4122bis-14</a> and is subject to change.</remarks>
	public static Guid CreateVersion7(TimeProvider timeProvider)
	{
		ArgumentNullException.ThrowIfNull(timeProvider);
		return CreateVersion7(timeProvider.GetUtcNow());
	}
#endif

	/// <summary>
	/// Creates a new Version 7 UUID from the specified timestamp.
	/// </summary>
	/// <param name="timestamp">The timestamp to be used to fill the <c>unix_ts_ms</c> field of the UUID.</param>
	/// <returns>A new time-based Version 7 UUID.</returns>
	/// <remarks>This method is based on <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-uuid-version-7">draft-ietf-uuidrev-rfc4122bis-14</a> and is subject to change.</remarks>
#if NET6_0_OR_GREATER
	[SkipLocalsInit]
#endif
	private static Guid CreateVersion7(DateTimeOffset timestamp)
	{
		var unixMilliseconds = timestamp.ToUnixTimeMilliseconds();
		if (unixMilliseconds < 0)
			throw new ArgumentOutOfRangeException(nameof(timestamp), timestamp, "The timestamp must be after 1 January 1970.");

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
	/// Creates a Version 8 UUID from 122 bits of the specified input. All byte values will be copied to the returned
	/// <see cref="Guid"/> except for the reserved <c>version</c> and <c>variant</c> bits, which will be set to 8
	/// and 2 respectively.
	/// </summary>
	/// <param name="bytes">The bytes to use to initialize the UUID.</param>
	/// <returns>A new Version 8 UUID.</returns>
	/// <remarks>This method treats the in MSB order; the first byte in <paramref name="bytes"/>
	/// will be the first byte in the standard string representation of the returned <see cref="Guid"/>.
	/// This is the opposite of how the <see cref="Guid(byte[])"/> constructor treats its argument, and
	/// will cause <see cref="Guid.ToByteArray()"/> to return a byte array whose bytes values are
	/// "reversed" compared to the input values in <paramref name="bytes"/>.
	/// This method is based on <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-uuid-version-8">draft-ietf-uuidrev-rfc4122bis-14</a> and is subject to change.</remarks>
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

		// convert the bytes to network order (so that bytes[0] is the first byte in the serialized GUID output)
		SwapByteOrder(guidBytes);

		// set the version and variant fields
		guidBytes[7] = (byte) (0x80 | (guidBytes[7] & 0xF));
		guidBytes[8] = (byte) (0x80 | (guidBytes[8] & 0x3F));

		return new Guid(guidBytes);
#endif
	}

#if NET6_0_OR_GREATER
	/// <summary>
	/// Creates a Version 8 UUID from 122 bits of the specified input. All byte values will be copied to the returned
	/// <see cref="Guid"/> except for the reserved <c>version</c> and <c>variant</c> bits, which will be set to 8
	/// and 2 respectively.
	/// </summary>
	/// <param name="bytes">The bytes to use to initialize the UUID.</param>
	/// <returns>A new Version 8 UUID.</returns>
	/// <remarks>This method treats the in MSB order; the first byte in <paramref name="bytes"/>
	/// will be the first byte in the standard string representation of the returned <see cref="Guid"/>.
	/// This is the opposite of how the <see cref="Guid(byte[])"/> constructor treats its argument, and
	/// will cause <see cref="Guid.ToByteArray()"/> to return a byte array whose bytes values are
	/// "reversed" compared to the input values in <paramref name="bytes"/>.
	/// This method is based on <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-uuid-version-8">draft-ietf-uuidrev-rfc4122bis-14</a> and is subject to change.</remarks>
	[SkipLocalsInit]
	public static Guid CreateVersion8(ReadOnlySpan<byte> bytes)
	{
		if (bytes.Length < 16)
			throw new ArgumentException("At least sixteen bytes must be provided", nameof(bytes));

		// make a copy of the bytes
		Span<byte> guidBytes = stackalloc byte[16];
		bytes[..16].CopyTo(guidBytes);

		// convert the bytes to network order (so that bytes[0] is the first byte in the serialized GUID output)
		SwapByteOrder(guidBytes);

		// set the version and variant fields
		guidBytes[7] = (byte) (0x80 | (guidBytes[7] & 0xF));
		guidBytes[8] = (byte) (0x80 | (guidBytes[8] & 0x3F));

		return new Guid(guidBytes);
	}
#endif

	/// <summary>
	/// Creates a Version 8 UUID from a name in the specified namespace using the specified hash algorithm, according to the algorithm
	/// in <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-name-based-uuid-generation">draft-ietf-uuidrev-rfc4122bis-14, section 6.5</a>.
	/// </summary>
	/// <param name="hashAlgorithmName">The name of the hash algorithm to use. Supported values are <c>SHA256</c>, <c>SHA384</c>, and <c>SHA512</c>.</param>
	/// <param name="namespaceId">The namespace ID.</param>
	/// <param name="name">The name within that namespace ID.</param>
	/// <returns>A version 8 UUID formed by hashing the hash space ID, namespace ID, and name.</returns>
	/// <remarks>This method is based on <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-name-based-uuid-generation">draft-ietf-uuidrev-rfc4122bis-14</a> and is subject to change.</remarks>
	public static Guid CreateVersion8FromName(HashAlgorithmName hashAlgorithmName, Guid namespaceId, byte[] name)
	{
#if NET6_0_OR_GREATER
		return CreateVersion8FromName(hashAlgorithmName, namespaceId, name.AsSpan());
#else
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

#if NET6_0_OR_GREATER
	/// <summary>
	/// Creates a Version 8 UUID from a name in the specified namespace using the specified hash algorithm, according to the algorithm
	/// in <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-name-based-uuid-generation">draft-ietf-uuidrev-rfc4122bis-14, section 6.5</a>.
	/// </summary>
	/// <param name="hashAlgorithmName">The name of the hash algorithm to use. Supported values are <c>SHA256</c>, <c>SHA384</c>, and <c>SHA512</c>.</param>
	/// <param name="namespaceId">The namespace ID.</param>
	/// <param name="name">The name within that namespace ID.</param>
	/// <returns>A version 8 UUID formed by hashing the hash space ID, namespace ID, and name.</returns>
	/// <remarks>This method is based on <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis-14#name-name-based-uuid-generation">draft-ietf-uuidrev-rfc4122bis-14</a> and is subject to change.</remarks>
	[SkipLocalsInit]
	public static Guid CreateVersion8FromName(HashAlgorithmName hashAlgorithmName, Guid namespaceId, ReadOnlySpan<byte> name)
	{
#if NET9_0_OR_GREATER
		Span<byte> hashOutput = stackalloc byte[64];
#else
		using var algorithm = GetHashAlgorithm(hashAlgorithmName);
		Span<byte> hashOutput = stackalloc byte[algorithm.HashSize / 8];
#endif
		Span<byte> buffer = name.Length < 500 ? stackalloc byte[16 + name.Length] : new byte[16 + name.Length];

		// convert the hash space and namespace UUIDs to network order
		if (!namespaceId.TryWriteBytes(buffer))
			throw new InvalidOperationException("Failed to write namespace ID bytes to buffer");
		SwapByteOrder(buffer);

		// compute the hash of [ namespace ID, name ]
		name.CopyTo(buffer[16..]);
#if NET9_0_OR_GREATER
		var hashLength = CryptographicOperations.HashData(hashAlgorithmName, buffer, hashOutput);
		if (hashLength == 0)
			throw new InvalidOperationException("Failed to hash data");
		hashOutput = hashOutput[..hashLength];
#else
		var success = algorithm.TryComputeHash(buffer, hashOutput, out var bytesWritten);
		if (!success || bytesWritten != hashOutput.Length)
			throw new InvalidOperationException("Failed to hash data");
#endif

		// the initial bytes from the hash are copied straight to the bytes of the new GUID
		var newGuid = hashOutput[..16];

		// set the version and variant bits
		newGuid[6] = (byte) ((newGuid[6] & 0x0F) | 0x80);
		newGuid[8] = (byte) ((newGuid[8] & 0x3F) | 0x80);

		// convert the resulting UUID to local byte order
		SwapByteOrder(newGuid);
		return new Guid(newGuid);
	}
#endif

#if !NET9_0_OR_GREATER
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

	// Converts a GUID (expressed as a byte array) to/from network order (MSB-first).
	internal static void SwapByteOrder(Span<byte> guid)
	{
		SwapBytes(guid, 0, 3);
		SwapBytes(guid, 1, 2);
		SwapBytes(guid, 4, 5);
		SwapBytes(guid, 6, 7);
	}

	private static void SwapBytes(Span<byte> guid, int left, int right)
	{
		ref var first = ref Unsafe.AsRef(in guid[0]);
		(Unsafe.Add(ref first, right), Unsafe.Add(ref first, left)) = (Unsafe.Add(ref first, left), Unsafe.Add(ref first, right));
	}

	// UUID v1 and v6 uses a count of 100-nanosecond intervals since 00:00:00.00 UTC, 15 October 1582
	private static readonly DateTime s_gregorianEpoch = new DateTime(1582, 10, 15, 0, 0, 0, DateTimeKind.Utc);
}
