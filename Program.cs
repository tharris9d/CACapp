using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using CACApp.Services;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .CreateLogger();

// Use Serilog for logging
builder.Host.UseSerilog();

try
{
    Log.Information("Starting CAC Application");

    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowAngular", policy =>
        {
            policy.WithOrigins("http://localhost:4200", "http://127.0.0.1:4200")
                  .AllowAnyHeader()
                  .AllowAnyMethod()
                  .AllowCredentials();
        });
    });

    builder.Services.AddSingleton<ICacReaderService, CacReaderService>();
    builder.Services.AddSingleton<ICertificateService, CertificateService>();
    builder.Services.AddSingleton<ICacValidationService, CacValidationService>();
    builder.Services.AddSingleton<ICertificateStorageService, CertificateStorageService>();
    builder.Services.AddSingleton<ICertificateExportService, CertificateExportService>();
    builder.Services.AddHttpClient();
    builder.Services.AddSingleton<ICrlOcspMonitoringService, CrlOcspMonitoringService>();

    var app = builder.Build();

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseRouting();
    app.UseCors("AllowAngular");
    app.UseAuthorization();
    app.MapControllers();

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
    throw;
}
finally
{
    Log.CloseAndFlush();
}
