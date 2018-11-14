using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Mindscape.Raygun4Net;
using Newtonsoft.Json;
using SkillsWorkflow.Services.ADBlocker.Models;
using SkillsWorkflow.Services.ADBlocker.Utils;

namespace SkillsWorkflow.Services.ADBlocker
{
    internal class Program
    {
        private static WebRequestHandler _handler;
        private static HttpClient _client;
        private static readonly RaygunClient RaygunClient = new RaygunClient(ConfigurationManager.AppSettings["Raygun:AppKey"]);

        private static void Main(string[] args)
        {
            InitializeRaygunClient();
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
            RunTaskAsync().Wait();
        }

        private static void InitializeRaygunClient()
        {
            var raygunJobName = ConfigurationManager.AppSettings["Raygun:JobName"];
            var raygunEnvironment = ConfigurationManager.AppSettings["Skills:Environment"];
            var raygunTags = new List<string> {raygunJobName, raygunEnvironment}.AsReadOnly();
            RaygunClient.SendingMessage += (sender, eventArgs) => { eventArgs.Message.Details.Tags = raygunTags; };
        }

        private static void ProcessException(Exception ex)
        {
            Trace.WriteLine("ERROR", "ADBlocker");
            ex.TraceError();
            RaygunClient.Send(ex);
        }

        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            RaygunClient.Send(e.ExceptionObject as Exception);
        }

        private static async Task RunTaskAsync()
        {
            Trace.WriteLine("Start task", "ADBlocker");
            Trace.WriteLine($"Start Time: {DateTime.UtcNow.ToString("dd/MM/yyyy HH:mm:ss.fff")}", "ADBlocker");
            try
            {
                InitializeHttpClient();
                await RunBlockingTaskAsync();
                await RunScheduledTaskAsync();
                await UpdateTaskRuntimeAsync();
            }
            catch (Exception ex)
            {
                ProcessException(ex);
            }
            finally
            {
                Trace.WriteLine($"End Time: {DateTime.UtcNow.ToString("dd/MM/yyyy HH:mm:ss.fff")}", "ADBlocker");
                Trace.WriteLine("End Task", "ADBlocker");
                Trace.WriteLine("");
                Trace.Close();
                _client?.Dispose();
                _handler?.Dispose();
            }
        }

        private static void InitializeHttpClient()
        {
            _handler = new WebRequestHandler();
            if(!ConfigurationManager.AppSettings["Skills:Environment"].ToLower().Equals("local"))
                _handler.ServerCertificateValidationCallback = PinPublicKey;
            _client = new HttpClient(_handler)
            {
                BaseAddress = new Uri(ConfigurationManager.AppSettings["Skills:ApiUrl"])
            };
            _client.DefaultRequestHeaders.Add("X-AppId", ConfigurationManager.AppSettings["Skills:AppId"]);
            _client.DefaultRequestHeaders.Add("X-AppSecret", ConfigurationManager.AppSettings["Skills:AppSecret"]);
            _client.DefaultRequestHeaders.Accept.Clear();
            _client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }

        private static async Task UpdateTaskRuntimeAsync()
        {
            var response = await _client.PostAsync("api/blockedloginrequests/taskruntime", new StringContent(""));
            response.EnsureSuccessStatusCode();
        }

        private static async Task RunBlockingTaskAsync()
        {
            try
            {
                Trace.WriteLine($"Started running blocking task: {DateTime.UtcNow.ToString("dd/MM/yyyy HH:mm:ss.fff")}",
                    "ADBlocker");
                var response = await _client.GetAsync("api/blockedloginrequests/userstoblock");
                response.EnsureSuccessStatusCode();
                var responseContent = await response.Content.ReadAsStringAsync();
                var usersToBlock = JsonConvert.DeserializeObject<List<User>>(responseContent);
                foreach (var user in usersToBlock)
                    await BlockUserAsync(user);
                Trace.WriteLine($"Ended running blocking task: {DateTime.UtcNow.ToString("dd/MM/yyyy HH:mm:ss.fff")}",
                    "ADBlocker");
            }
            catch (Exception ex)
            {
                ProcessException(ex);
            }
            
        }

        private static async Task RunScheduledTaskAsync()
        {
            Trace.WriteLine($"Started running scheduled task: {DateTime.UtcNow.ToString("dd/MM/yyyy HH:mm:ss.fff")}", "ADBlocker");

            await ProcessBlockedLoginRequestsAsync();
            await ProcessUnblockUserRequestsAsync();

            Trace.WriteLine($"Ended running scheduled task: {DateTime.UtcNow.ToString("dd/MM/yyyy HH:mm:ss.fff")}", "ADBlocker");
        }

        private static async Task ProcessBlockedLoginRequestsAsync()
        {
            try
            {
                var response = await _client.GetAsync("api/blockedloginrequests");
                response.EnsureSuccessStatusCode();
                var resp = await response.Content.ReadAsStringAsync();
                var blockedLoginRequests = JsonConvert.DeserializeObject<List<BlockedLoginRequest>>(resp);

                foreach (var blockedLoginRequest in blockedLoginRequests)
                    await UpdateBlockedLoginRequestAsync(ValidateLoginRequest(blockedLoginRequest));
            }
            catch (Exception ex)
            {
                ProcessException(ex);
            }
        }

        private static async Task ProcessUnblockUserRequestsAsync()
        {
            try
            {
                var response = await _client.GetAsync("api/unblockuserrequests");
                response.EnsureSuccessStatusCode();
                var responseContent = await response.Content.ReadAsStringAsync();
                var unblockUserRequests = JsonConvert.DeserializeObject<List<UnblockUserRequest>>(responseContent);
                foreach (var unblockUserRequest in unblockUserRequests)
                    await ProcessUnblockUserRequestAsync(unblockUserRequest);
            }
            catch (Exception ex)
            {
                ProcessException(ex);
            }
        }

        private static async Task ProcessUnblockUserRequestAsync(UnblockUserRequest unblockUserRequest)
        {
            UnblockUserRequestResult result;
            using (var context = CreatePrincipalContext())
            {
                using (UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(context, unblockUserRequest.AdUserName))
                {
                    if (userPrincipal == null)
                        result = new UnblockUserRequestResult { Id = unblockUserRequest.Id, RequestResult = false, RequestResultMessage = "AD User not found." };
                    else
                    {
                        string updateField = ConfigurationManager.AppSettings["AD:UpdateField"];
                        if (string.IsNullOrWhiteSpace(updateField))
                        {
                            if (userPrincipal.AccountExpirationDate.HasValue &&
                                userPrincipal.AccountExpirationDate.Value < DateTime.UtcNow)
                            {
                                if (!unblockUserRequest.AccountExpirationDate.HasValue || (unblockUserRequest.AccountExpirationDate.Value > DateTime.UtcNow))
                                    userPrincipal.AccountExpirationDate = unblockUserRequest.AccountExpirationDate;
                                else
                                    userPrincipal.AccountExpirationDate = null;
                            }
                        }
                        else
                        {
                            var entry = userPrincipal.GetUnderlyingObject() as DirectoryEntry;
                            if (entry != null)
                            {
                                var value = GetValueForFieldUpdate(entry.Properties[updateField], ConfigurationManager.AppSettings["AD:UpdateFieldEnableValue"]);
                                entry.Properties[updateField].Clear();
                                entry.Properties[updateField].Add(value);
                            }
                            else
                            {
                                Trace.WriteLine($"Unblocked User {unblockUserRequest.AdUserName} failed. The defined update field is invalid or the user entry could not be loaded.", "ADBlocker");
                                result = new UnblockUserRequestResult { Id = unblockUserRequest.Id, RequestResult = false,
                                    RequestResultMessage = "Operation failed. The defined update field is invalid or the user entry could not be loaded." };
                                await UpdateUnblockRequest(result);
                                return;
                            }
                                
                        }
  
                        userPrincipal.Save();
                        result = new UnblockUserRequestResult { Id = unblockUserRequest.Id, RequestResult = true, RequestResultMessage = "" };
                        Trace.WriteLine($"Unblocked User {unblockUserRequest.AdUserName}", "ADBlocker");
                    }
                }
            }
            await UpdateUnblockRequest(result);
        }

        private static async Task UpdateUnblockRequest(UnblockUserRequestResult result)
        {
            HttpContent putContent = new StringContent(JsonConvert.SerializeObject(result), Encoding.UTF8, "application/json");
            var response = await _client.PutAsync("api/unblockuserrequests", putContent);
            response.EnsureSuccessStatusCode();
        }

        private static PrincipalContext CreatePrincipalContext()
        {
            return new PrincipalContext(ContextType.Domain, ConfigurationManager.AppSettings["AD:Domain"], 
                ConfigurationManager.AppSettings["AD:User"], ConfigurationManager.AppSettings["AD:Password"]);
        }

        private static BlockedLoginRequestResult ValidateLoginRequest(BlockedLoginRequest blockedLoginRequest)
        {
            bool valid = false;
            
            using (var context = CreatePrincipalContext())
            {
                using (UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(context, blockedLoginRequest.AdUserName))
                {
                    if (userPrincipal == null)
                    {
                        Trace.WriteLine($"User {blockedLoginRequest.AdUserName} not found in AD.", "ADBlocker");
                        return new BlockedLoginRequestResult { Id = blockedLoginRequest.Id, RequestResult = false, RequestResultMessage = "AD User not found." };
                    }

                    string updateField = ConfigurationManager.AppSettings["AD:UpdateField"];
                    if (string.IsNullOrWhiteSpace(updateField))
                    {
                        DateTime? accountExpirationDate = userPrincipal.AccountExpirationDate;

                        if (accountExpirationDate.HasValue && accountExpirationDate.Value < DateTime.UtcNow)
                        {
                            userPrincipal.AccountExpirationDate = DateTime.UtcNow.AddYears(1);
                            userPrincipal.Save();
                        }

                        Trace.WriteLine($"User {blockedLoginRequest.AdUserName} unblocked", "ADBlocker");
                        var entries = blockedLoginRequest.AdUserName.Split(new[] { "\\" }, StringSplitOptions.RemoveEmptyEntries);
                        var user = entries.Length == 2 ? entries[1] : entries[0];
                        valid = context.ValidateCredentials(user, blockedLoginRequest.Password);
                        Trace.WriteLine($"UserName: {blockedLoginRequest.AdUserName} ", "ADBlocker");

                        userPrincipal.AccountExpirationDate = accountExpirationDate;
                        userPrincipal.Save();
                        Trace.WriteLine($"User {blockedLoginRequest.AdUserName} blocked", "ADBlocker");
                    }
                    else
                    {
                        var entry = userPrincipal.GetUnderlyingObject() as DirectoryEntry;
                        if (entry != null)
                        {
                            var oldValue = entry.Properties[updateField].Value;
                            var value = GetValueForFieldUpdate(entry.Properties[updateField], ConfigurationManager.AppSettings["AD:UpdateFieldEnableValue"]);
                            entry.Properties[updateField].Clear();
                            entry.Properties[updateField].Add(value);
                            userPrincipal.Save();
                            Trace.WriteLine($"User {blockedLoginRequest.AdUserName} unblocked", "ADBlocker");
                            var entries = blockedLoginRequest.AdUserName.Split(new[] { "\\" }, StringSplitOptions.RemoveEmptyEntries);
                            var user = entries.Length == 2 ? entries[1] : entries[0];
                            valid = context.ValidateCredentials(user, blockedLoginRequest.Password);
                            Trace.WriteLine($"UserName: {blockedLoginRequest.AdUserName} ", "ADBlocker");
                            entry.Properties[updateField].Clear();
                            entry.Properties[updateField].Add(oldValue);
                            userPrincipal.Save();
                            Trace.WriteLine($"User {blockedLoginRequest.AdUserName} blocked", "ADBlocker");
                        }
                        else
                            Trace.WriteLine($"Could not validate user credentials. The update field is invalid or the user entry could not be loaded.", "ADBlocker");
                    }
                        
                }
            }

            return new BlockedLoginRequestResult { Id = blockedLoginRequest.Id, RequestResult = valid, RequestResultMessage = valid ? "" : "AD User credentials are invalid." };
        }

        private static async Task UpdateBlockedLoginRequestAsync(BlockedLoginRequestResult result)
        {
            HttpContent putContent = new StringContent(JsonConvert.SerializeObject(result), Encoding.UTF8, "application/json");
            var response = await _client.PutAsync("api/blockedloginrequests", putContent);
            response.EnsureSuccessStatusCode();
        }

        private static async Task<bool> BlockUserAsync(User user)
        {
            using (var context = CreatePrincipalContext())
            {
                using (UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(context, user.AdUserName))
                {
                    if (userPrincipal == null)
                    {
                        Trace.WriteLine($"User {user.AdUserName} not found in AD.", "ADBlocker");
                        return false;
                    }

                    DateTime? adLockExpirationDate = null;
                    string updateField = ConfigurationManager.AppSettings["AD:UpdateField"];
                    if (string.IsNullOrWhiteSpace(updateField))
                    {
                        if (userPrincipal.AccountExpirationDate.HasValue &&
                        userPrincipal.AccountExpirationDate.Value < DateTime.UtcNow)
                        {
                            Trace.WriteLine($"User {user.AdUserName} is already blocked and was not processed again.", "ADBlocker");
                            await UpdateBlockStatus(user, null);
                            return false;
                        }
                        adLockExpirationDate = userPrincipal.AccountExpirationDate;
                        userPrincipal.AccountExpirationDate = DateTime.UtcNow.AddYears(-1);
                    }
                    else
                    {
                        var entry = userPrincipal.GetUnderlyingObject() as DirectoryEntry;
                        if (entry != null)
                        {
                            var value = GetValueForFieldUpdate(entry.Properties[updateField], ConfigurationManager.AppSettings["AD:UpdateFieldDisableValue"]);
                            entry.Properties[updateField].Clear();
                            entry.Properties[updateField].Add(value);
                        }
                        else
                        {
                            Trace.WriteLine($"User {user.AdUserName} was not processed. The update field is invalid or the user entry could not be loaded.", "ADBlocker");
                            return false;
                        }
                    }
                    
                    userPrincipal.Save();

                    await UpdateBlockStatus(user, adLockExpirationDate);
                }
            }
            Trace.WriteLine($"Blocked User {user.AdUserName}", "ADBlocker");
            return true;
        }

        private static async Task<bool> UpdateBlockStatus(User user, DateTime? adLockExpirationDate)
        {
            HttpContent postContent = new StringContent(JsonConvert.SerializeObject(new UserToBlock { Oid = user.Oid, AccountExpirationDate = adLockExpirationDate }), Encoding.UTF8, "application/json");
            var response = await _client.PostAsync("api/blockedloginrequests/block", postContent);
            response.EnsureSuccessStatusCode();
            return true;
        }

        private static bool PinPublicKey(object sender, X509Certificate certificate, X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            var pk = certificate?.GetPublicKeyString();
            return pk != null && pk.Equals(ConfigurationManager.AppSettings["Skills:SSLPublicKey"]);
        }

        private static object GetValueForFieldUpdate(PropertyValueCollection property, string stringValue)
        {
            if(property.PropertyName == "logonHours")
                return ConvertHexaStringToByteArray(stringValue);
            if (property.Value == null)
                return stringValue;
            if (property.Value.GetType() == typeof(byte[]))
                return ConvertHexaStringToByteArray(stringValue);
            return stringValue;
        }

        private static byte[] ConvertHexaStringToByteArray(string hexString)
        {
            var bytes = new byte[hexString.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
    }
}
