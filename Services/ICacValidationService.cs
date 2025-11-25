using System.Security.Cryptography.X509Certificates;

namespace CACApp.Services;

public interface ICacValidationService
{
    Task<ValidationResult> ValidateCacOnlineAsync(X509Certificate2 certificate);
}

public class ValidationResult
{
    public bool IsValid { get; set; }
    public string Status { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public List<string> Details { get; set; } = new();
    public DateTime ValidationTime { get; set; } = DateTime.Now;
    public bool OnlineValidationFailed { get; set; }
    public string? OnlineValidationFailureReason { get; set; }
}

