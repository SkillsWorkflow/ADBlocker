# ADBlocker

On premises agent to block and unblock users on the Active Directory based on missing timesheets in Skills Workflow

<h3>Framework/Tools/Dependencies</h3>
<ul>
<li>.NET Framework 4.5.2</li>
<li>Visual Studio 2015 or later</li>
</ul>

<h3>Running Instructions - Windows</h3>
<ol>
<li>Download the source code and open the solution in Visual Studio.</li>
<li>Open <strong>app.config</strong> file and change the app settings accordingly. These settings are explained further below.</li>
<li>Run the application</li>
</ol>

<h3>Scheduling Instructions - Windows</h3>
<ol>
<li>ADBlocker application should be run as a Scheduled Task. Create a new Scheduled Task in Task Scheduler.</li>
<li>Manage the created Task. Choose a user with permissions to run the task and set a trigger to run the task in repeat mode.</li>
<li>The ADBlocker task should run with a recurring short period of time.</li>
<li>Set the task to run the ADBlocker.exe file. No entry parameters are required</li>
</ol>

<h3>ADBlocker Settings</h3>
<ol>
<li><strong>Active Directory</strong></li>
<li>This are the credentials for the Active Directory you're accessing.</li>
<ul>
<li><strong>AD:Domain</strong> - This setting should be parametrized with the Active Directory domain.</li>
<li><strong>AD:User</strong> - Active Directory User Username. This user should have permissions to block/unblock users from the Active Directory.</li>
<li><strong>AD:Password</strong> - Active Directory User password.</li>
</ul>
<li><strong>SkillsWorkflow</strong>
<ul>
<li><strong>Skills:ApiUrl</strong> - SkillsWorkflow Api base url. It depends on the Environment and Tenant being used. It has the following scructure https://api-tenant-environment-we.skillsworkflow.com. Use the name of the company provided to you for the parameter "tenant". For "environment" use "prod", "test" or "dev" for one of Skills Workflow's Environments: Production, Testing, Development.</li>
<li><strong>Skills:AppId</strong> - SkillsWorkflow Tenant application id. This id must be requested to SkillsWorkflow team. It will be used to ensure comunication with SkillsWorkflow api.</li>
<li><strong>Skills:AppSecret</strong> - SkillsWorkflow Tenant application secret. It is used with Tenant application id.</li>
<li><strong>Skills:SSLPublicKey</strong> - SkillsWorkflow SSL certificate public key. It is used to validate requests to SkillsWorkflow Api. This key must be requested to SkillsWorkflow team.</li>
<li><strong>Skills:Environment</strong> - AdBlocker application environment settings. When set to "Local" it will disable SSL certificate validations and application errors will be registered accordingly. To use SSL certificate validation use "Production" mode. Use "Production", "Test", "Development" or "Local" depending on the environment the application is being deployed.
</ul>
</li>
<li><strong>Raygun</strong>
<ul>
<li><strong>Raygun:JobName</strong> - Parameter used to group information in Raygun logging platform. Default value is "ADBlocker".</li>
<li><strong>Raygun:AppKey</strong> - Raygun platform access key. This key must be requested to SkillsWorkflow team. </li>
</ul>
</li>
</ol>
