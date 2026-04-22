using Microsoft.Extensions.Logging;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;

internal sealed class ListLogger<T> : ILogger<T>
{
    public List<LogEntry> Entries { get; } = [];

    public IDisposable BeginScope<TState>(TState state)
        where TState : notnull
        => NullScope.Instance;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        Entries.Add(new LogEntry(logLevel, eventId, formatter(state, exception), exception));
    }

    internal sealed record LogEntry(LogLevel Level, EventId EventId, string Message, Exception? Exception);

    private sealed class NullScope : IDisposable
    {
        public static NullScope Instance { get; } = new();

        public void Dispose()
        {
        }
    }
}

internal sealed class ListLoggerFactory : ILoggerFactory
{
    public List<LogEntry> Entries { get; } = [];

    public void AddProvider(ILoggerProvider provider)
    {
    }

    public ILogger CreateLogger(string categoryName) => new Logger(categoryName, Entries);

    public void Dispose()
    {
    }

    internal sealed record LogEntry(string Category, LogLevel Level, EventId EventId, string Message, Exception? Exception);

    private sealed class Logger(string categoryName, List<LogEntry> entries) : ILogger
    {
        public IDisposable BeginScope<TState>(TState state)
            where TState : notnull
            => SharedNullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            entries.Add(new LogEntry(categoryName, logLevel, eventId, formatter(state, exception), exception));
        }
    }

    private sealed class SharedNullScope : IDisposable
    {
        public static SharedNullScope Instance { get; } = new();

        public void Dispose()
        {
        }
    }
}
