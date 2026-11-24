using Xunit;

namespace StruggleBusMonitor.Tests;

public class EnrollmentNamesTests
{
    [Theory]
    [InlineData("adlab-cli-win")]
    [InlineData("build-agent")]
    [InlineData("  Build Agent  ")]
    [InlineData("build_agent__2")]
    public void AgentNamesTheBusAcceptsPass(string typed) =>
        Assert.Null(EnrollmentNames.Problem(NameRule.Agent, typed));

    [Theory]
    [InlineData("buildagent", "Agent names need at least one hyphen, joining a project and a platform, for example adlab-cli-win.")]
    [InlineData("build.agent", "Agent names can only use lowercase letters, digits and hyphens. Remove: .")]
    [InlineData("build.agent@home.pc", "Agent names can only use lowercase letters, digits and hyphens. Remove: . @")]
    [InlineData("-build-agent", "Agent names cannot start or end with a hyphen, or have two hyphens in a row.")]
    [InlineData("_build_agent_", "Agent names cannot start or end with a hyphen, or have two hyphens in a row.")]
    public void ARefusedAgentNameSaysWhatIsWrong(string typed, string expected) =>
        Assert.Equal(expected, EnrollmentNames.Problem(NameRule.Agent, typed));

    [Fact]
    public void NamesHaveALengthLimit()
    {
        var longest = "a-" + new string('b', 126);
        Assert.Null(EnrollmentNames.Problem(NameRule.Agent, longest));
        Assert.Equal("Agent names are limited to 128 characters; this one has 129.", EnrollmentNames.Problem(NameRule.Agent, longest + "c"));
        Assert.Equal("Device labels are limited to 64 characters; this one has 65.", EnrollmentNames.Problem(NameRule.Device, new string('d', 65)));
    }

    [Fact]
    public void AnEmptyNameIsLeftToTheMissingFieldMessage()
    {
        Assert.Null(EnrollmentNames.Problem(NameRule.Agent, "   "));
        Assert.Equal(NameFeedback.None, EnrollmentNames.Feedback(NameRule.Agent, ""));
    }

    [Fact]
    public void DeviceLabelsDoNotNeedAHyphen()
    {
        Assert.Null(EnrollmentNames.Problem(NameRule.Device, "laptop"));
        Assert.Null(EnrollmentNames.Problem(NameRule.Device, "Spare Laptop"));
        Assert.Equal("Device labels can only use lowercase letters, digits and hyphens. Remove: !", EnrollmentNames.Problem(NameRule.Device, "laptop!"));
    }

    [Fact]
    public void ServicePrincipalNamesAndPrefixesAreNotTidiedByTheBus()
    {
        Assert.Null(EnrollmentNames.Problem(NameRule.ServicePrincipal, " Nightly-Audit "));
        Assert.Null(EnrollmentNames.Problem(NameRule.Prefix, "audit"));
        Assert.Equal("Service principal names can only use lowercase letters, digits and hyphens. Remove: space", EnrollmentNames.Problem(NameRule.ServicePrincipal, "nightly audit"));
        Assert.Equal("Agent name prefixes can only use lowercase letters, digits and hyphens. Remove: _", EnrollmentNames.Problem(NameRule.Prefix, "audit_worker"));
        Assert.Equal("Agent name prefixes cannot start or end with a hyphen, or have two hyphens in a row.", EnrollmentNames.Problem(NameRule.Prefix, "audit--worker"));
    }

    [Fact]
    public void TheNameIsShownAsTheBusWillStoreIt()
    {
        Assert.Equal("build-agent", EnrollmentNames.Canonical(NameRule.Agent, " Build  Agent "));
        Assert.Equal("nightly-audit", EnrollmentNames.Canonical(NameRule.ServicePrincipal, " Nightly-Audit "));
        Assert.Equal(new NameFeedback("Will be created as build-agent", false), EnrollmentNames.Feedback(NameRule.Agent, "Build Agent"));
        Assert.Equal(NameFeedback.None, EnrollmentNames.Feedback(NameRule.Agent, " build-agent "));
        Assert.True(EnrollmentNames.Feedback(NameRule.Agent, "buildagent").IsProblem);
    }

    [Theory]
    [InlineData(EnrollmentKind.Agent, "Agent names")]
    [InlineData(EnrollmentKind.Device, "Device labels")]
    [InlineData(EnrollmentKind.ServicePrincipal, "Service principal names")]
    public void EachKindOfEnrollmentHasItsOwnRule(EnrollmentKind kind, string noun) =>
        Assert.Equal(noun, NameRule.For(kind).Noun);
}
