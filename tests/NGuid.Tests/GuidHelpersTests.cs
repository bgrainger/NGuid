namespace NGuid.Tests;

public class GuidHelpersTests
{
	[Fact]
	public void SwapByteOrder()
	{
		Guid guid = new Guid(0x01020304, 0x0506, 0x0708, 9, 10, 11, 12, 13, 14, 15, 16);
		byte[] bytes = guid.ToByteArray();
		Assert.Equal(new byte[] { 4, 3, 2, 1, 6, 5, 8, 7, 9, 10, 11, 12, 13, 14, 15, 16 }, bytes);

		GuidHelpers.SwapByteOrder(bytes);
		Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }, bytes);
	}

	[Fact]
	public void CreateVersion3FromWidgetsCom()
	{
		// run the test case from RFC 4122 Appendix B, as updated by http://www.rfc-editor.org/errata_search.php?rfc=4122
		Guid guid = GuidHelpers.Create(GuidHelpers.DnsNamespace, "www.widgets.com", 3);
		Assert.Equal(new Guid("3d813cbb-47fb-32ba-91df-831e1593ac29"), guid);
	}

	[Fact]
	public void CreateVersion3FromPythonOrg()
	{
		// run the test case from the Python implementation (http://docs.python.org/library/uuid.html#uuid-example)
		Guid guid = GuidHelpers.Create(GuidHelpers.DnsNamespace, "python.org", 3);
		Assert.Equal(new Guid("6fa459ea-ee8a-3ca4-894e-db77e160355e"), guid);
	}

	[Fact]
	public void CreateVersion5FromPythonOrg()
	{
		// run the test case from the Python implementation (http://docs.python.org/library/uuid.html#uuid-example)
		Guid guid = GuidHelpers.Create(GuidHelpers.DnsNamespace, "python.org", 5);
		Assert.Equal(new Guid("886313e1-3b8a-5372-9b90-0c9aee199e5d"), guid);
	}

	[Fact]
	public void CreateNullName()
	{
		var ex = Assert.Throws<ArgumentNullException>(() => GuidHelpers.Create(GuidHelpers.DnsNamespace, null!));
		Assert.Equal("name", ex.ParamName);
	}

	[Fact]
	public void CreateInvalidVersion()
	{
		var ex = Assert.Throws<ArgumentOutOfRangeException>(() => GuidHelpers.Create(GuidHelpers.DnsNamespace, "www.example.com", 4));
		Assert.Equal("version", ex.ParamName);
	}
}
