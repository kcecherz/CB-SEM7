using System.Globalization;

namespace Klucznik.Security;

public static class ClockFormat
{
    private static readonly CultureInfo Polish = CultureInfo.GetCultureInfo("pl-PL");

    public static string Display(DateTimeOffset value) =>
        value.ToLocalTime().ToString("d MMMM yyyy, HH:mm", Polish);
}
