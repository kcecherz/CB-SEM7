using System.Security.Cryptography;

namespace Klucznik.Security;

public static class OneTimePasswordFactory
{
    public const int WordCount = 4;
    public static readonly TimeSpan Lifetime = TimeSpan.FromHours(24);

    public static readonly string[] Words =
    [
        "koń", "rower", "zima", "lampa", "most", "okno", "las", "rzeka",
        "chmura", "klucz", "drzwi", "mapa", "pies", "wiatr", "deszcz", "słońce",
        "morze", "góra", "pole", "droga", "wieża", "brama", "ogród", "kwiat",
        "liść", "kamień", "piasek", "jezioro", "wyspa", "statek", "pociąg", "kotwica",
        "latarnia", "komin", "piekarnia", "biblioteka", "zeszyt", "ołówek", "papier", "atrament",
        "pieczęć", "archiwum", "skrzynia", "powróz", "dzwonek", "świeca", "podłoga", "sufit",
        "schody", "piwnica", "strych", "furtka", "ścieżka", "łąka", "sosna", "dąb",
        "jemioła", "bursztyn", "miedź", "srebro", "zboże", "mąka", "miód", "serce",
    ];

    public static string Generate()
    {
        var used = new HashSet<int>();
        var picked = new string[WordCount];
        var index = 0;
        while (index < WordCount)
        {
            var candidate = RandomNumberGenerator.GetInt32(Words.Length);
            if (!used.Add(candidate))
                continue;

            picked[index] = Words[candidate];
            index++;
        }

        return string.Join('-', picked);
    }
}
