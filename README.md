# HelloID-Conn-SA-Full-Google-Group-AddOrRemoveUser

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-SA-Full-Google-Group-AddOrRemoveUser/blob/main/Logo.png?raw=true">
</p>

## Table of contents

- [HelloID-Conn-SA-Full-Google-Group-AddOrRemoveUser](#helloid-conn-sa-full-google-group-addorremoveuser)
  - [Table of contents](#table-of-contents)
  - [Requirements](#requirements)
  - [Remarks](#remarks)
  - [Introduction](#introduction)
      - [Description](#description)
      - [Endpoints](#endpoints)
      - [Form Options](#form-options)
      - [Task Actions](#task-actions)
  - [Connector Setup](#connector-setup)
    - [Create a Google Cloud project](#create-a-google-cloud-project)
    - [Enable Google Workspace APIs](#enable-google-workspace-apis)
    - [Create access credentials](#create-access-credentials)
      - [Create a service account](#create-a-service-account)
    - [Create credentials for a service account](#create-credentials-for-a-service-account)
    - [Set up domain-wide delegation for a service account](#set-up-domain-wide-delegation-for-a-service-account)
    - [Variable Library - User Defined Variables](#variable-library---user-defined-variables)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Requirements
1. **HelloID Environment**:
   - Set up your _HelloID_ environment.
   - Install the _HelloID_ Service Automation agent (cloud or on-prem).
2. **Google API Credentials**:
   - Create a project in the Google Cloud Console.
   - Enable the Admin SDK API for your project.
   - Create access credentials for your project:
     - Create a service account for your project.
     - Generate credentials (P12 key) for your service account.
     - Set up domain-wide delegation for your service account with the following scopes:
       - `https://www.googleapis.com/auth/admin.directory.group`
       - `https://www.googleapis.com/auth/admin.directory.user`

## Remarks
- None.

## Introduction

#### Description
_HelloID-Conn-SA-Full-Google-Group-AddOrRemoveUser_ is a template designed for use with HelloID Service Automation (SA) Delegated Forms. It can be imported into HelloID and customized according to your requirements. 

By using this delegated form, you gain the ability to seamlessly manage Google Workspace Groupmemberships.

#### Endpoints
Google Workspace provides a set of REST APIs that allow you to programmatically interact with its data.. The API endpoints listed in the table below are used.

| Endpoint                                                                                                                                        | Description                     |
| ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| [/admin/directory/v1/groups/{groupKey}/members](https://developers.google.com/admin-sdk/directory/reference/rest/v1/members/insert)             | Add user to group (POST)        |
| [/admin/directory/v1/groups/{groupKey}/members/{memberKey}](https://developers.google.com/admin-sdk/directory/reference/rest/v1/members/delete) | Remove user from group (DELETE) |
| [/admin/directory/v1/users](https://developers.google.com/admin-sdk/directory/reference/rest/v1/users/list)                                     | List users (GET)                |
| [/admin/directory/v1/groups](https://developers.google.com/admin-sdk/directory/reference/rest/v1/groups/list)                                   | List groups (GET)               |

#### Form Options
The following options are available in the form:

1. **Search by Exact Email Address and Select Google Group**: Users can search for an exact email address and choose a Google group.
2. **Search by Exact Email Address and Select Google User**: Users can search for an exact email address and choose a Google user.
3. **Select Action to Perform**: Users can choose between "Add User to Group" or "Remove User from Group."

#### Task Actions
The following actions will be performed based on user selections:

1. **Add User to Group**:
   - If the user selects this action, the chosen user will be added to the selected group.
2. **Remove User from Group**:
   - If the user selects this action, the chosen user will be removed from the selected group.

## Connector Setup
### Create a Google Cloud project
The first step to connect to the Google API and make requests is to register a new **Google Cloud project**. This project is required to use Google Workspace APIs.

Follow these steps:
1. Go to the Google Cloud Console.
2. Create a new project.

For more information, please see: [Create a Google Cloud project](https://developers.google.com/workspace/guides/create-project).

### Enable Google Workspace APIs
Next, enable the necessary Google Workspace APIs in your Google Cloud project. For this connector, we use the **Admin SDK API**.

Follow these steps:

1. In your Google Cloud project, navigate to the “APIs & Services” > “Library” section.
2. Search for “Admin SDK” and enable it.

For more information, please see: [Enable Google Workspace APIs](https://developers.google.com/workspace/guides/enable-apis).

### Create access credentials
There are multiple ways to authenticate to the Google API, but we use (and recommend) the service account credentials.

#### Create a service account
A service account is a special kind of account used by an application (rather than a person). You can use a service account to access data or perform actions on behalf of Google Workspace or Cloud Identity users.

Follow these steps:

1. In your Google Cloud project, navigate to the “APIs & Services” > “Credentials” section.
2. Create a new service account.
3. Note down the service account email address.

For more information, please see: [Create a service account](https://developers.google.com/workspace/guides/create-credentials#create_a_service_account).

### Create credentials for a service account
To authorize service account actions within your app, you need to obtain credentials in the form of a public/private key pair. We recommend using the P12 key type.

Follow these steps:

1. In the “Credentials” section, create a new key for your service account.
2. Choose the P12 key type.
3. Download the P12 key file and securely store it.

For more information, please see: [Create credentials for a service account](https://developers.google.com/workspace/guides/create-credentials#create_credentials_for_a_service_account).

### Set up domain-wide delegation for a service account
To call APIs on behalf of users in a Google Workspace organization, your service account needs to be granted domain-wide delegation of authority in the Google Workspace Admin console by a super administrator account.

The following scopes are required:

- `https://www.googleapis.com/auth/admin.directory.group`
- `https://www.googleapis.com/auth/admin.directory.user`

For more information, please see: [Set up domain-wide delegation for a service account](https://developers.google.com/workspace/guides/create-credentials#optional_set_up_domain-wide_delegation_for_a_service_account).

### Variable Library - User Defined Variables
The following user-defined variables are used by the connector. Ensure that you check and set the correct values required to connect to the API.

| Setting                        | Description                                                                                                                                                               |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GoogleServiceAccountEmail`    | The email address of your service account                                                                                                                                 |
| `GoogleP12CertificateBase64`   | The Base64 string of the P12 certificate of your service account                                                                                                          |
| `GoogleP12CertificatePassword` | The password to the P12 certificate of your service account                                                                                                               |
| `GoogleAdminEmail`             | The email address of an admin account with permissions to manage groups and users                                                                                         |
| `GoogleUsersOrgUnitPath`       | The full path of an organizational unit. This matches all organizational unit chains under the target. For example, `orgUnitPath=/` returns all users in the organization |

**Note:** The Base64 string of the P12 certificate file can be obtained by running the following code:
```powershell
[System.Convert]::ToBase64String((Get-Content "C:\path\to\your\certificate.p12" -Encoding Byte))
```

## Getting help
> [!TIP]
> _For more information on Delegated Forms, please refer to our [documentation](https://docs.helloid.com/en/service-automation/delegated-forms.html) pages_.

> [!TIP]
>  _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_.

## HelloID docs
The official HelloID documentation can be found at: https://docs.helloid.com/