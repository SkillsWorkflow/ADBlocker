using System;
using System.Collections.Generic;
using System.Configuration;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using log4net;
using Mindscape.Raygun4Net;
using Newtonsoft.Json;
using SkillsWorkflow.Services.ADBlocker.Models;

namespace SkillsWorkflow.Services.ADBlocker
{
    internal class Program
    {
        private static WebRequestHandler _handler;
        private static HttpClient _client;
        private static readonly RaygunClient RaygunClient = new RaygunClient(ConfigurationManager.AppSettings["Raygun:AppKey"]);
        private static readonly ILog _logger = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

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
            _logger.Error("ERROR", ex);
            RaygunClient.Send(ex);
        }

        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            RaygunClient.Send(e.ExceptionObject as Exception);
        }

        private static async Task RunTaskAsync()
        {
            _logger.Info("Start Task");
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
                _logger.Info("End Task");
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
            _client.DefaultRequestHeaders.Add("X-AppTenant", ConfigurationManager.AppSettings["Skills:AppTenant"]);
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
            _logger.Info("Started running blocking task");
            var response = await _client.GetAsync("api/blockedloginrequests/userstoblock");
            response.EnsureSuccessStatusCode();
            var responseContent = await response.Content.ReadAsStringAsync();
            var usersToBlock = JsonConvert.DeserializeObject<List<User>>(responseContent);
            foreach (var user in usersToBlock)
                await BlockUserAsync(user);
            _logger.Info("Ended running blocking task");
        }

        private static async Task RunScheduledTaskAsync()
        {
            _logger.Info("Started running scheduled task");
            await ProcessBlockedLoginRequestsAsync();
            await ProcessUnblockUserRequestsAsync();
            _logger.Info("Ended running scheduled task");
        }

        private static async Task ProcessBlockedLoginRequestsAsync()
        {
            var response = await _client.GetAsync("api/blockedloginrequests");
            response.EnsureSuccessStatusCode();
            var resp = await response.Content.ReadAsStringAsync();
            var blockedLoginRequests = JsonConvert.DeserializeObject<List<BlockedLoginRequest>>(resp);

            foreach (var blockedLoginRequest in blockedLoginRequests)
                await UpdateBlockedLoginRequestAsync(ValidateLoginRequest(blockedLoginRequest));
        }

        private static async Task ProcessUnblockUserRequestsAsync()
        {
            var response = await _client.GetAsync("api/unblockuserrequests");
            response.EnsureSuccessStatusCode();
            var responseContent = await response.Content.ReadAsStringAsync();
            var unblockUserRequests = JsonConvert.DeserializeObject<List<UnblockUserRequest>>(responseContent);
            foreach (var unblockUserRequest in unblockUserRequests)
                await ProcessUnblockUserRequestAsync(unblockUserRequest);
        }

        private static async Task ProcessUnblockUserRequestAsync(UnblockUserRequest unblockUserRequest)
        {
            UnblockUserRequestResult result;
            try
            {
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
                                    _logger.Warn($"Unblocked User {unblockUserRequest.AdUserName} failed. The defined update field is invalid or the user entry could not be loaded.");
                                    result = new UnblockUserRequestResult
                                    {
                                        Id = unblockUserRequest.Id,
                                        RequestResult = false,
                                        RequestResultMessage = "Operation failed. The defined update field is invalid or the user entry could not be loaded."
                                    };
                                    await UpdateUnblockRequest(result);
                                    return;
                                }

                            }

                            userPrincipal.Save();
                            result = new UnblockUserRequestResult { Id = unblockUserRequest.Id, RequestResult = true, RequestResultMessage = "" };
                            _logger.Info($"Unblocked User {unblockUserRequest.AdUserName}");
                        }
                    }
                }

            }
            catch(Exception ex)
            {
                ProcessException(ex);
                result = new UnblockUserRequestResult { Id = unblockUserRequest.Id, RequestResult = false, RequestResultMessage = ex.Message };
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

            try
            {
                using (var context = CreatePrincipalContext())
                {
                    using (UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(context, blockedLoginRequest.AdUserName))
                    {
                        if (userPrincipal == null)
                        {
                            _logger.Warn($"User {blockedLoginRequest.AdUserName} not found in AD.");
                            return new BlockedLoginRequestResult { Id = blockedLoginRequest.Id, RequestResult = false, RequestResultMessage = "AD User not found." };
                        }

                        _logger.Info("Starting blocked login request validation.");
                        string updateField = ConfigurationManager.AppSettings["AD:UpdateField"];
                        if (string.IsNullOrWhiteSpace(updateField))
                        {
                            DateTime? accountExpirationDate = userPrincipal.AccountExpirationDate;

                            if (accountExpirationDate.HasValue && accountExpirationDate.Value < DateTime.UtcNow)
                            {
                                userPrincipal.AccountExpirationDate = DateTime.UtcNow.AddYears(1);
                                userPrincipal.Save();
                            }

                            _logger.Info($"User {blockedLoginRequest.AdUserName} unblocked");
                            var entries = blockedLoginRequest.AdUserName.Split(new[] { "\\" }, StringSplitOptions.RemoveEmptyEntries);
                            var user = entries.Length == 2 ? entries[1] : entries[0];
                            valid = context.ValidateCredentials(user, blockedLoginRequest.Password);
                            _logger.Info($"UserName: {blockedLoginRequest.AdUserName} ");

                            userPrincipal.AccountExpirationDate = accountExpirationDate;
                            userPrincipal.Save();
                            _logger.Info($"User {blockedLoginRequest.AdUserName} blocked");
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
                                _logger.Info($"User {blockedLoginRequest.AdUserName} unblocked");
                                var entries = blockedLoginRequest.AdUserName.Split(new[] { "\\" }, StringSplitOptions.RemoveEmptyEntries);
                                var user = entries.Length == 2 ? entries[1] : entries[0];
                                valid = context.ValidateCredentials(user, blockedLoginRequest.Password);
                                _logger.Info($"UserName: {blockedLoginRequest.AdUserName} ");
                                entry.Properties[updateField].Clear();
                                entry.Properties[updateField].Add(oldValue);
                                userPrincipal.Save();
                                _logger.Info($"User {blockedLoginRequest.AdUserName} blocked");
                            }
                            else
                                _logger.Warn("Could not validate user credentials. The update field is invalid or the user entry could not be loaded.");
                        }
                        _logger.Info("Ended blocked login request validation.");
                    }
                }

                return new BlockedLoginRequestResult { Id = blockedLoginRequest.Id, RequestResult = valid, RequestResultMessage = valid ? "" : "AD User credentials are invalid." };
            }
            catch(Exception ex)
            {
                ProcessException(ex);
                return new BlockedLoginRequestResult { Id = blockedLoginRequest.Id, RequestResult = false, RequestResultMessage = ex.Message };
            }
        }

        private static async Task UpdateBlockedLoginRequestAsync(BlockedLoginRequestResult result)
        {
            HttpContent putContent = new StringContent(JsonConvert.SerializeObject(result), Encoding.UTF8, "application/json");
            var response = await _client.PutAsync("api/blockedloginrequests", putContent);
            response.EnsureSuccessStatusCode();
        }

        private static async Task<bool> BlockUserAsync(User user)
        {
            try
            {
                using (var context = CreatePrincipalContext())
                {
                    using (UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(context, user.AdUserName))
                    {
                        if (userPrincipal == null)
                        {
                            _logger.Warn($"User {user.AdUserName} not found in AD.");
                            await UpdateBlockStatus(user, null, false, $"User {user.AdUserName} not found in AD.");
                            return false;
                        }

                        DateTime? adLockExpirationDate = null;
                        string updateField = ConfigurationManager.AppSettings["AD:UpdateField"];
                        if (string.IsNullOrWhiteSpace(updateField))
                        {
                            if (userPrincipal.AccountExpirationDate.HasValue &&
                            userPrincipal.AccountExpirationDate.Value < DateTime.UtcNow)
                            {
                                _logger.Info($"User {user.AdUserName} is already blocked and was not processed again.");
                                await UpdateBlockStatus(user, null, true, string.Empty);
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
                                _logger.Warn($"User {user.AdUserName} was not processed. The update field is invalid or the user entry could not be loaded.");
                                await UpdateBlockStatus(user, null, false, $"User {user.AdUserName} was not processed. The update field is invalid or the user entry could not be loaded.");
                                return false;
                            }
                        }

                        userPrincipal.Save();

                        await UpdateBlockStatus(user, adLockExpirationDate, true, string.Empty);
                    }
                }
                _logger.Info($"Blocked User {user.AdUserName}");
                return true;
            }
            catch(Exception ex)
            {
                _logger.Error($"Error Blocking User: {user.AdUserName}");
                await UpdateBlockStatus(user, null, false, ex.ToString());
                ProcessException(ex);
                return false;
            }
        }

        private static async Task<bool> UpdateBlockStatus(User user, DateTime? adLockExpirationDate, bool success, string message)
        {
            HttpContent postContent = new StringContent(JsonConvert.SerializeObject(new UserToBlock { Oid = user.Oid, AccountExpirationDate = adLockExpirationDate, Success = success, Message = message }), Encoding.UTF8, "application/json");
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
