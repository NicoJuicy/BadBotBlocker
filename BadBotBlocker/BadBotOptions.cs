using System.Net;

namespace BadBotBlocker;

/// <summary>
/// Represents the options for the BadBotBlocker.
/// </summary>
public sealed class BadBotOptions
{
    /// <summary>
    /// Gets the list of bad bot patterns.
    /// </summary>
    public List<string> BadBotPatterns { get; } = [];

    /// <summary>
    /// Gets the list of blocked IP ranges.
    /// </summary>
    public List<(IPAddress NetworkAddress, int PrefixLength)> BlockedIPRanges { get; } = [];

    /// <summary>
    /// Gets the list of honeypot path patterns. Requests matching these patterns will cause the client IP to be temporarily banned.
    /// </summary>
    public List<string> HoneypotPathPatterns { get; } = [];

    /// <summary>
    /// Gets or sets the duration for which an IP is banned after hitting a honeypot path. Defaults to 5 minutes.
    /// </summary>
    public TimeSpan HoneypotBanDuration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Initializes a new instance of the <see cref="BadBotOptions"/> class.
    /// </summary>
    public BadBotOptions()
    {
        // Load default patterns and IP ranges
        this.LoadDefaultBadBotPatterns();
        this.LoadDefaultBlockedIPRanges();
        this.LoadDefaultHoneypotPathPatterns();
    }

    /// <summary>
    /// Adds a bad bot pattern to the list.
    /// </summary>
    /// <param name="pattern">The bad bot pattern to add.</param>
    /// <returns>The <see cref="BadBotOptions"/> instance.</returns>
    public BadBotOptions AddBadBotPattern(string pattern)
    {
        this.BadBotPatterns.Add(pattern);
        return this;
    }

    /// <summary>
    /// Adds a blocked IP range to the list.
    /// </summary>
    /// <param name="cidr">The CIDR notation representing the blocked IP range.</param>
    /// <returns>The <see cref="BadBotOptions"/> instance.</returns>
    /// <exception cref="FormatException">Thrown when the CIDR notation is invalid.</exception>
    public BadBotOptions AddBlockedIPRange(string cidr)
    {
        var parts = cidr.Split('/');

        if (parts.Length != 2)
        {
            throw new FormatException("Invalid CIDR notation");
        }

        var networkAddress = IPAddress.Parse(parts[0]);
        var prefixLength = int.Parse(parts[1]);

        this.BlockedIPRanges.Add((networkAddress, prefixLength));

        return this;
    }

    /// <summary>
    /// Clears the list of bad bot patterns.
    /// </summary>
    /// <returns>The <see cref="BadBotOptions"/> instance.</returns>
    public BadBotOptions ClearBadBotPatterns()
    {
        this.BadBotPatterns.Clear();
        return this;
    }

    /// <summary>
    /// Clears the list of blocked IP ranges.
    /// </summary>
    /// <returns>The <see cref="BadBotOptions"/> instance.</returns>
    public BadBotOptions ClearBlockedIPRanges()
    {
        this.BlockedIPRanges.Clear();
        return this;
    }

    /// <summary>
    /// Adds a honeypot path pattern. Paths containing this value (case-insensitive) will trigger a temporary IP ban.
    /// </summary>
    /// <param name="pattern">The path pattern to trap (e.g., ".php", ".git").</param>
    /// <returns>The <see cref="BadBotOptions"/> instance.</returns>
    public BadBotOptions AddHoneypotPathPattern(string pattern)
    {
        this.HoneypotPathPatterns.Add(pattern);
        return this;
    }

    /// <summary>
    /// Clears the list of honeypot path patterns.
    /// </summary>
    /// <returns>The <see cref="BadBotOptions"/> instance.</returns>
    public BadBotOptions ClearHoneypotPathPatterns()
    {
        this.HoneypotPathPatterns.Clear();
        return this;
    }

    /// <summary>
    /// Loads the default honeypot path patterns.
    /// </summary>
    private void LoadDefaultHoneypotPathPatterns()
    {
        this.HoneypotPathPatterns.AddRange([
            ".php",
            ".git",
            ".env",
            "wp-admin",
            "wp-login",
            "wp-content",
            "wp-includes",
            "xmlrpc",
            "/cgi-bin/",
            "/admin/",
            "phpmyadmin",
        ]);
    }

    /// <summary>
    /// Loads the default bad bot patterns.
    /// </summary>
    private void LoadDefaultBadBotPatterns()
    {
        var patterns = new[]
        {
            "^Aboundex",
            "^80legs",
            "^360Spider",
            "^Java",
            "^Cogentbot",
            "^Alexibot",
            "^asterias",
            "^attach",
            "^BackDoorBot",
            "^BackWeb",
            "Bandit",
            "^BatchFTP",
            "^Bigfoot",
            "^Black.Hole",
            "^BlackWidow",
            "^BlowFish",
            "^BotALot",
            "Buddy",
            "^BuiltBotTough",
            "^Bullseye",
            "^BunnySlippers",
            "^Cegbfeieh",
            "^CheeseBot",
            "^CherryPicker",
            "^ChinaClaw",
            "Collector",
            "Copier",
            "^CopyRightCheck",
            "^cosmos",
            "^Crescent",
            "^Custo",
            "^AIBOT",
            "^DISCo",
            "^DIIbot",
            "^DittoSpyder",
            "^Download Demon",
            "^Download Devil",
            "^Download Wonder",
            "^dragonfly",
            "^Drip",
            "^eCatch",
            "^EasyDL",
            "^ebingbong",
            "^EirGrabber",
            "^EmailCollector",
            "^EmailSiphon",
            "^EmailWolf",
            "^EroCrawler",
            "^Exabot",
            "^Express WebPictures",
            "Extractor",
            "^EyeNetIE",
            "^Foobot",
            "^flunky",
            "^FrontPage",
            "^Go-Ahead-Got-It",
            "^gotit",
            "^GrabNet",
            "^Grafula",
            "^Harvest",
            "^hloader",
            "^HMView",
            "^HTTrack",
            "^humanlinks",
            "^IlseBot",
            "^Image Stripper",
            "^Image Sucker",
            "Indy Library",
            "^InfoNaviRobot",
            "^InfoTekies",
            "^Intelliseek",
            "^InterGET",
            "^Internet Ninja",
            "^Iria",
            "^Jakarta",
            "^JennyBot",
            "^JetCar",
            "^JOC",
            "^JustView",
            "^Jyxobot",
            "^Kenjin.Spider",
            "^Keyword.Density",
            "^larbin",
            "^LexiBot",
            "^lftp",
            "^libWeb/clsHTTP",
            "^likse",
            "^LinkextractorPro",
            "^LinkScan/8.1a.Unix",
            "^LNSpiderguy",
            "^LinkWalker",
            "^lwp-trivial",
            "^LWP::Simple",
            "^Magnet",
            "^Mag-Net",
            "^MarkWatch",
            "^Mass Downloader",
            "^Mata.Hari",
            "^Memo",
            "^Microsoft.URL",
            "^Microsoft URL Control",
            "^MIDown tool",
            "^MIIxpc",
            "^Mirror",
            "^Missigua Locator",
            "^Mister PiX",
            "^moget",
            "^Mozilla/3.Mozilla/2.01",
            "^Mozilla.*NEWT",
            "^NAMEPROTECT",
            "^Navroad",
            "^NearSite",
            "^NetAnts",
            "^Netcraft",
            "^NetMechanic",
            "^NetSpider",
            "^Net Vampire",
            "^NetZIP",
            "^NextGenSearchBot",
            "^NG",
            "^NICErsPRO",
            "^niki-bot",
            "^NimbleCrawler",
            "^Ninja",
            "^NPbot",
            "^Octopus",
            "^Offline Explorer",
            "^Offline Navigator",
            "^Openfind",
            "^OutfoxBot",
            "^PageGrabber",
            "^Papa Foto",
            "^pavuk",
            "^pcBrowser",
            "^PHP version tracker",
            "^Pockey",
            "^ProPowerBot/2.14",
            "^ProWebWalker",
            "^psbot",
            "^Pump",
            "^QueryN.Metasearch",
            "^RealDownload",
            "Reaper",
            "Recorder",
            "^ReGet",
            "^RepoMonkey",
            "^RMA",
            "Siphon",
            "^SiteSnagger",
            "^SlySearch",
            "^SmartDownload",
            "^Snake",
            "^Snapbot",
            "^Snoopy",
            "^sogou",
            "^SpaceBison",
            "^SpankBot",
            "^spanner",
            "^Sqworm",
            "Stripper",
            "Sucker",
            "^SuperBot",
            "^SuperHTTP",
            "^Surfbot",
            "^suzuran",
            "^Szukacz/1.4",
            "^tAkeOut",
            "^Teleport",
            "^Telesoft",
            "^TurnitinBot/1.5",
            "^The.Intraformant",
            "^TheNomad",
            "^TightTwatBot",
            "^Titan",
            "^True_Robot",
            "^turingos",
            "^TurnitinBot",
            "^URLy.Warning",
            "^Vacuum",
            "^VCI",
            "^VoidEYE",
            "^Web Image Collector",
            "^Web Sucker",
            "^WebAuto",
            "^WebBandit",
            "^Webclipping.com",
            "^WebCopier",
            "^WebEMailExtrac.*",
            "^WebEnhancer",
            "^WebFetch",
            "^WebGo IS",
            "^Web.Image.Collector",
            "^WebLeacher",
            "^WebmasterWorldForumBot",
            "^WebReaper",
            "^WebSauger",
            "^Website eXtractor",
            "^Website Quester",
            "^Webster",
            "^WebStripper",
            "^WebWhacker",
            "^WebZIP",
            "Whacker",
            "^Widow",
            "^WISENutbot",
            "^WWWOFFLE",
            "^WWW-Collector-E",
            "^Xaldon",
            "^Xenu",
            "^Zeus",
            "ZmEu",
            "^Zyborg",
            // Vulnerability Scanners
            "Acunetix",
            "FHscan",
            // Aggressive Chinese Search Engine
            "Baiduspider",
            // Aggressive Russian Search Engine
            "Yandex"
        };

        this.BadBotPatterns.AddRange(patterns);
    }

    /// <summary>
    /// Loads the default blocked IP ranges.
    /// </summary>
    private void LoadDefaultBlockedIPRanges()
    {
        var ipRanges = new[]
        {
            // Cyveillance
            "38.100.19.8/29",
            "38.100.21.0/24",
            "38.100.41.64/26",
            "38.105.71.0/25",
            "38.105.83.0/27",
            "38.112.21.140/30",
            "38.118.42.32/29",
            "65.213.208.128/27",
            "65.222.176.96/27",
            "65.222.185.72/29"
        };

        foreach (var cidr in ipRanges)
        {
            this.AddBlockedIPRange(cidr);
        }
    }
}
