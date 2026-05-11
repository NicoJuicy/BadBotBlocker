using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace BadBotBlocker;

/// <summary>
/// Represents the middleware for blocking bad bots.
/// </summary>
public sealed partial class BadBotMiddleware
{
    private const string HoneypotCacheKeyPrefix = "BadBotBlocker:Honeypot:";

    private readonly RequestDelegate next;
    private readonly IMemoryCache memoryCache;
    private readonly List<IPatternMatcher> badBotMatchers;
    private readonly List<(IPAddress NetworkAddress, int PrefixLength)> blockedIPRanges;
    private readonly List<string> honeypotPathPatterns;
    private readonly TimeSpan honeypotBanDuration;

    /// <summary>
    /// Initializes a new instance of the <see cref="BadBotMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware delegate.</param>
    /// <param name="options">The options for the BadBotMiddleware.</param>
    /// <param name="memoryCache">The memory cache used for honeypot IP bans.</param>
    public BadBotMiddleware(RequestDelegate next, IOptions<BadBotOptions> options, IMemoryCache memoryCache)
    {
        this.next = next;
        this.memoryCache = memoryCache;

        var badBotOptions = options.Value;

        this.badBotMatchers = badBotOptions
            .BadBotPatterns.Select(pattern =>
                IsStartsWithPattern(pattern)
                    ? new StartsWithPatternMatcher(pattern.TrimStart('^')) as IPatternMatcher
                    : new RegexPatternMatcher(pattern)
            )
            .ToList();

        this.blockedIPRanges = badBotOptions.BlockedIPRanges;
        this.honeypotPathPatterns = badBotOptions.HoneypotPathPatterns;
        this.honeypotBanDuration = badBotOptions.HoneypotBanDuration;
    }

    private static bool IsStartsWithPattern(string pattern)
    {
        if (!pattern.StartsWith('^'))
        {
            return false;
        }

        var trimmedPattern = pattern[1..];

        // Check for regex special characters
        return !SpecialCharacterPattern().IsMatch(trimmedPattern);
    }

    /// <summary>
    /// Invokes the middleware.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    public async Task InvokeAsync(HttpContext context)
    {
        // Check IP address
        var ipAddress = context.Connection.RemoteIpAddress;

        if (ipAddress != null)
        {
            // Check honeypot ban
            var cacheKey = HoneypotCacheKeyPrefix + ipAddress;

            if (this.memoryCache.TryGetValue(cacheKey, out _))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }

            foreach (var (networkAddress, prefixLength) in this.blockedIPRanges)
            {
                if (ipAddress.IsInSubnet(networkAddress, prefixLength))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return;
                }
            }
        }

        // Check User-Agent
        var userAgent = context.Request.Headers["User-Agent"].ToString();

        if (!string.IsNullOrEmpty(userAgent))
        {
            foreach (var matcher in this.badBotMatchers)
            {
                if (matcher.IsMatch(userAgent))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return;
                }
            }
        }

        // Check honeypot paths
        if (ipAddress != null && this.honeypotPathPatterns.Count > 0)
        {
            var path = context.Request.Path.Value;

            if (!string.IsNullOrEmpty(path))
            {
                foreach (var pattern in this.honeypotPathPatterns)
                {
                    if (path.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        var cacheKey = HoneypotCacheKeyPrefix + ipAddress;
                        this.memoryCache.Set(cacheKey, true, this.honeypotBanDuration);
                        context.Response.StatusCode = StatusCodes.Status403Forbidden;
                        return;
                    }
                }
            }
        }

        await this.next(context);
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"[\.\$\*\+\?\{\}\[\]\|\\]")]
    private static partial System.Text.RegularExpressions.Regex SpecialCharacterPattern();
}
