<h1>Sample Auth Backend</h1>

Virtualenv is a tool that lets you create an isolated Python environment for your project. It creates an environment that has its own installation directories.

<h2>Installation</h2>
<p>To install virtualenv run:</p>
<code>pip install virtualenv</code>
<br><br>
<p>Go to the Project Directory</p>
<code>cd "project dir"</code>
<br><br>
<p>Set up virtualenv for that project by running:</p>
<code>virtualenv venv</code>
<br><br>
<p>This command creates a venv/ directory in your project where all dependencies are installed. You need to activate it first though (in every terminal instance where you are working on your project):</p>

<code>source venv/bin/activate</code>
<br><br>
<p>You should see a (venv) appear at the beginning of your terminal prompt indicating that you are working inside the virtualenv.<br><br> Now you can install all packages by running:</p>

<code>pip install -r requirements.txt</code>

<br /><br />
<h3>Running the app</h3>
<p>Then run app using:</p>
<code>flask run</code>
<br><br>

<h2>db migration</h2>
<p>You can create a migration repository with the following command:</p>
<code>flask db init</code>
<br><br>
<p>You can then generate an initial migration:</p>
<code>flask db migrate</code>
<br><br>
<p>Then you can apply the migration to the database:</p>
<code>flask db upgrade</code>
<br><br>


<h2>List of APIs</h2>
<b>Register a user</b> -  <code>POST /users</code>(Form-data) - Name, email, password, device_token, device_type, gender.

<b>Login</b> -  <code>POST /login</code>(application/json) - email, password, device_token, device_type

<b>Forgot Password</b> -  <code>POST /forgotPassword</code>(application/json) - email

<b>Forgot Password API from email URL</b> -  <code>POST /forgot/\<token\></code>(application/json) - password

<b>Edit User API</b> -  <code>PUT /user</code>(application/json) - keys needed to be changed like email, name, etc.

<b>Login with access token</b> -  <code>GET /user</code>(application/json) - access_token required in headers.

<b>Change password API</b> -  <code>POST /changePassword</code>(application/json) - oldPassword, newPassword.

<b>Skip login</b> -  <code>POST /login/skip</code>(application/json) - device_token, device_type