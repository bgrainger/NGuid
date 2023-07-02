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
	/// <remarks>This method is based on <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis#name-uuid-version-6">draft-ietf-uuidrev-rfc4122bis-07</a> and is subject to change.</remarks>
	public static Guid CreateVersion6() =>
		CreateVersion6(DateTimeOffset.UtcNow);

#if NET8_0_OR_GREATER
	/// <summary>
	/// Creates a new Version 6 UUID based on the timestamp returned from <paramref name="timeProvider"/> and a random node ID.
	/// </summary>
	/// <param name="timeProvider">A <see cref="TimeProvider"/> that can provide the current UTC time.</param>
	/// <returns>A new Version 6 UUID based on the specified time and a random node ID.</returns>
	/// <remarks>This method is based on <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis#name-uuid-version-6">draft-ietf-uuidrev-rfc4122bis-07</a> and is subject to change.</remarks>
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
	/// <remarks>This method is based on <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis#name-uuid-version-6">draft-ietf-uuidrev-rfc4122bis-07</a> and is subject to change.</remarks>
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
	/// <remarks>This method is based on <a href="https://datatracker.ietf.org/doc/html/draft-ietf-uuidrev-rfc4122bis#name-uuid-version-6">draft-ietf-uuidrev-rfc4122bis-07</a> and is subject to change.</remarks>
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
		ref var first = ref Unsafe.AsRef(guid[0]);
		(Unsafe.Add(ref first, right), Unsafe.Add(ref first, left)) = (Unsafe.Add(ref first, left), Unsafe.Add(ref first, right));
	}

	// UUID v1 and v6 uses a count of 100-nanosecond intervals since 00:00:00.00 UTC, 15 October 1582
	private static readonly DateTime s_gregorianEpoch = new DateTime(1582, 10, 15, 0, 0, 0, DateTimeKind.Utc);
}
