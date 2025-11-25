using System.Security.Cryptography.X509Certificates;

namespace CACApp.Services;

public interface ICacReaderService
{
    Task<bool> IsReaderAvailableAsync();
    Task<List<string>> GetAvailableReadersAsync();
    Task<X509Certificate2?> ReadCacCertificateAsync(string? readerName = null, string? pin = null);
    Task<bool> PromptForPinAsync();
    event EventHandler<string>? StatusChanged;
}

