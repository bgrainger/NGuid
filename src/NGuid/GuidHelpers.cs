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
	/// Creates a deterministic name-based UUID using the algorithm from <a href="https://datatracker.ietf.org/doc/html/rfc4122#section-4.3">RFC 4122 §4.3</a>.
	/// </summary>
	/// <param name="namespaceId">The ID of the namespace.</param>
	/// <param name="name">The name (within that namespace).</param>
	/// <param name="version">The version number of the UUID to create; this value must be either
	/// 3 (for MD5 hashing) or 5 (for SHA-1 hashing).</param>
	/// <returns>A UUID derived from the namespace and name.</returns>
	public static Guid CreateDeterministic(Guid namespaceId, string name, int version = 5)
	{
		// see https://github.com/LogosBible/Logos.Utility/blob/master/src/Logos.Utility/GuidUtility.cs and https://faithlife.codes/blog/2011/04/generating_a_deterministic_guid/ for the original version of this code
#if NET6_0_OR_GREATER
		ArgumentNullException.ThrowIfNull(name);
#else
		if (name is null)
			throw new ArgumentNullException(nameof(name));
#endif
		if (version is not (3 or 5))
			throw new ArgumentOutOfRangeException(nameof(version), version, "version must be either 3 or 5.");

		// convert the name to a sequence of octets (as defined by the standard or conventions of its namespace) (step 3)
		// ASSUME: UTF-8 encoding is always appropriate
		var nameBytes = Encoding.UTF8.GetBytes(name);

		// convert the namespace UUID to network order (step 3)
		var namespaceBytes = namespaceId.ToByteArray();
		SwapByteOrder(namespaceBytes);

		// compute the hash of the name space ID concatenated with the name (step 4)
		byte[] hash;
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
#pragma warning disable CA5351 // Do Not Use Broken Cryptographic Algorithms
		using (var algorithm = version == 3 ? (HashAlgorithm) MD5.Create() : SHA1.Create())
		{
			algorithm.TransformBlock(namespaceBytes, 0, namespaceBytes.Length, null, 0);
			algorithm.TransformFinalBlock(nameBytes, 0, nameBytes.Length);
			hash = algorithm.Hash!;
		}
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
}
