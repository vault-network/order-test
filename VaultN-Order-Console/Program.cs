// See https://aka.ms/new-console-template for more information

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Serilog;
using ILogger = Microsoft.Extensions.Logging.ILogger;

public class Program
{
    public static void Main(string[] args)
    {
        Log.Logger = new LoggerConfiguration()
            .WriteTo.File("logs/log.txt", rollingInterval: RollingInterval.Day)
            .CreateLogger();
        // Add HostBuilder to create a new host
        var host = Host.CreateDefaultBuilder(args)
            .ConfigureAppConfiguration((host, config) =>
            {
                config.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);
                config.Build();
            })
            .ConfigureServices((host,services) =>
            {
                services.AddLogging();
                services.AddHttpClient("default", client =>
                {
                    client.BaseAddress = new Uri("https://sbx-api.vaultn.com/api/v3/");
                   

                }).ConfigurePrimaryHttpMessageHandler<HttpRequestLogger>();
                services.AddTransient<HttpRequestLogger>();
                services.AddTransient<OrderTestService>();
            })
            .Build();
        
        var testService = host.Services.GetRequiredService<OrderTestService>();
        //6d23e8b5-9ae9-4bac-8793-eb33c724a247 => Dino
        //d9106126-c006-44fe-850c-90743347396f => Infinite Games
        //VAUL-GA-STE-2024TESTPR-COM-RO
        var sku = "VAUL-GA-STE-2024TESTPR-COM-RO";
        var ownerGuids = new List<string>(){ "6d23e8b5-9ae9-4bac-8793-eb33c724a247", "d9106126-c006-44fe-850c-90743347396f" };
        foreach (var ownerGuid in ownerGuids)
        {
            testService.CreateOrder(ownerGuid, sku).Wait();
            Task.Delay(5000).Wait();
        }
        
    }
}


public class OrderTestService(IHttpClientFactory httpClientFactory)
{
    private string CreateToken(string ownerGuid, string pfxFile, string pfxPassword)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var cert = new X509Certificate2(pfxFile,pfxPassword);
    
        var cred = new X509SigningCredentials(cert);
    
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = "Self",
            Audience = "VaultN",
            Subject = new ClaimsIdentity(new Claim[]
            {
            
                new Claim(JwtRegisteredClaimNames.Sub, ownerGuid.ToUpper())
            }),
            Expires = DateTime.UtcNow.AddMinutes(30),
            SigningCredentials = cred

        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var retval = tokenHandler.WriteToken(token);
        return retval;
    }

    public async Task CreateOrder(string ownerGuid,string sku)
    {
        var pfxFile = "generic.pfx";
        var pfxPassword = "1q2w3e";
        var agreementGuid = "9BCB1DED-1904-4A98-9D55-F985B9DD2EBE"; // Default(Public) Agreement
        using var client = httpClientFactory.CreateClient("default");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", CreateToken(ownerGuid,pfxFile,pfxPassword));
        
        var response = await client.PostAsync("order/createorder",new StringContent(
            JsonConvert.SerializeObject(new OrderPayload
            {
                Sku = sku,
                IpAddress = "20.126.147.237",
                CurrencyCode = "EUR",
                PriceAmount = 50,
                AppliedDiscount = 0,
                ClientReference = Guid.NewGuid().ToString(),
                AgreementGUID = agreementGuid
            })
            , Encoding.UTF8, "application/json")
        );
        var content = await response.Content.ReadAsStringAsync();
        Console.WriteLine(content);
    }
}
public class HttpRequestLogger : DelegatingHandler
{
    Dictionary<string,string> owners = new Dictionary<string,string>(){{"6d23e8b5-9ae9-4bac-8793-eb33c724a247","DINO GAMES"},{"d9106126-c006-44fe-850c-90743347396f","INFINITE GAMES"}};
    public HttpRequestLogger():base(new HttpClientHandler())
    {
        
    }
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        
        Log.Logger.Information("Request: {Method} {Uri}", request.Method, request.RequestUri);
        var token = request.Headers.Authorization?.Parameter;
        
        if (token != null)
        {
            var jwt = new JwtSecurityToken(token);
            Log.Logger.Information("Owner: {Owner}", owners.GetValueOrDefault(jwt.Subject.ToLower()));
            Log.Logger.Information("Owner GUID: {OwnerGuid}", jwt.Subject);
            
        }
        if (request.Content != null)
        {
            Log.Logger.Information("Request Content: {Content}", await request.Content.ReadAsStringAsync());
        }
        var response = await base.SendAsync(request, cancellationToken);
        Log.Logger.Information("Response: {StatusCode}", response.StatusCode);
        if (response.Content != null)
        {
            Log.Logger.Information("Response Content: {Content}", await response.Content.ReadAsStringAsync());
        }
        Log.Logger.Information("---------------------------------");
        return response;
    }
}

public class OrderPayload
{
    public string Sku { get; set; }
    public string IpAddress { get; set; }
    public string CurrencyCode { get; set; }
    public decimal PriceAmount { get; set; }
    public decimal AppliedDiscount { get; set; }
    public string ClientReference { get; set; }
    public string AgreementGUID { get; set; }
}


