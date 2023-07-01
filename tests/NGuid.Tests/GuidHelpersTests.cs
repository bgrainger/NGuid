namespace NGuid.Tests;

public class GuidHelpersTests
{
	[Fact]
	public void SwapByteOrder()
	{
		var guid = new Guid(0x01020304, 0x0506, 0x0708, 9, 10, 11, 12, 13, 14, 15, 16);
		var bytes = guid.ToByteArray();
		Assert.Equal(new byte[] { 4, 3, 2, 1, 6, 5, 8, 7, 9, 10, 11, 12, 13, 14, 15, 16 }, bytes);

		GuidHelpers.SwapByteOrder(bytes);
		Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }, bytes);
	}

	[Theory]
	[InlineData("www.widgets.com", 3, "3d813cbb-47fb-32ba-91df-831e1593ac29" /*, TestDisplayName = "RFC 4122 Appendix B, as updated by http://www.rfc-editor.org/errata_search.php?rfc=4122" */)]
	[InlineData("www.widgets.com", 5, "21f7f8de-8051-5b89-8680-0195ef798b6a" /*, TestDisplayName = "Boost Test Suite https://github.com/boostorg/uuid/blob/2bc0c8e71677f387afdc09bc4f8d609d2c74e80e/test/test_generators.cpp#L85C25-L85C121" */)]
	[InlineData("python.org", 3, "6fa459ea-ee8a-3ca4-894e-db77e160355e" /*, TestDisplayName = "Python implementation (http://docs.python.org/library/uuid.html#uuid-example)" */)]
	[InlineData("python.org", 5, "886313e1-3b8a-5372-9b90-0c9aee199e5d" /*, TestDisplayName = "Python implementation (http://docs.python.org/library/uuid.html#uuid-example)" */)]
	public void CreateDeterministicDnsGuid(string name, int version, string expected) =>
		Assert.Equal(new Guid(expected), GuidHelpers.CreateDeterministic(GuidHelpers.DnsNamespace, name, version));

	[Fact]
	public void CreateNullName()
	{
		var ex = Assert.Throws<ArgumentNullException>(() => GuidHelpers.CreateDeterministic(GuidHelpers.DnsNamespace, null!));
		Assert.Equal("name", ex.ParamName);
	}

	[Fact]
	public void CreateInvalidVersion()
	{
		var ex = Assert.Throws<ArgumentOutOfRangeException>(() => GuidHelpers.CreateDeterministic(GuidHelpers.DnsNamespace, "www.example.com", 4));
		Assert.Equal("version", ex.ParamName);
	}
}
