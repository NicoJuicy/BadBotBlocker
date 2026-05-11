using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;

namespace BadBotBlocker;

/// <summary>
/// Extension methods for configuring BadBotMiddleware in the ASP.NET Core pipeline.
/// </summary>
public static class BadBotMiddlewareExtensions
{
    /// <summary>
    /// Adds the BadBotMiddleware to the request pipeline.
    /// </summary>
    /// <param name="builder">The <see cref="IApplicationBuilder"/> instance.</param>
    /// <returns>The <see cref="IApplicationBuilder"/> instance.</returns>
    public static IApplicationBuilder UseBadBotBlocker(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<BadBotMiddleware>();
    }

    /// <summary>
    /// Adds the BadBotMiddleware services to the specified <see cref="IServiceCollection"/>.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> instance.</param>
    /// <param name="configureOptions">An optional action to configure the <see cref="BadBotOptions"/>.</param>
    /// <returns>The <see cref="IServiceCollection"/> instance.</returns>
    public static IServiceCollection AddBadBotBlocker(
        this IServiceCollection services,
        Action<BadBotOptions>? configureOptions = null
    )
    {
        services.AddMemoryCache();

        if (configureOptions != null)
        {
            services.Configure(configureOptions);
        }
        else
        {
            services.AddSingleton<BadBotOptions>();
        }

        return services;
    }
}
