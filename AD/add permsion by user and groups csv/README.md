# Script to Grant Permissions in AD Based on CSV File

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Description

This PowerShell script allows you to grant permissions to resources in Active Directory (AD) based on data contained in a CSV file. The script enables you to add permissions for specific users and groups, making it easier to manage access to resources in the AD environment.

## Features

- **Import Data from CSV File:**
  - The script reads data about users, groups, and resources to which permissions are to be granted from a CSV file.

- **Granting Permissions for Users:**
  - Adding specific permissions (e.g., read, write) for specific users to selected resources.

- **Granting Permissions for Groups:**
  - Adding permissions for AD groups, allowing you to manage permissions at the group level instead of individual users.

- **Logging:**
  - Recording all executed operations in a log, making it easier to monitor and troubleshoot.

- **Error Handling:**
  - The script includes error handling mechanisms that inform you of problems during permission assignment (e.g., user or resource not found).

## Requirements

- Active Directory module for PowerShell
- CSV file with properly formatted data
- Permissions to modify permissions in Active Directory

## Usage

1. **Preparing the CSV File:**
   - Create a CSV file with columns containing information about users, groups, and resources to which permissions are to be granted.
   - Ensure that the column headers match the names used in the script (e.g., `Username`, `GroupName`, `ResourcePath`, `PermissionType`).

2. **Script Configuration:**
   - Open the PowerShell script and adjust the configuration variables (e.g., path to the CSV file, path to the log file) to your environment.

3. **Running the Script:**
   - Run the PowerShell script with administrator privileges.
   - The script will read data from the CSV file and grant permissions according to the information contained in it.

4. **Checking Logs:**
   - Review the log file to ensure that all operations were performed correctly and that no errors occurred.

## Sample CSV File

```csv
Username,GroupName,ResourcePath,PermissionType
user1,group1,\\server\share1,Read
user2,group2,\\server\share2,Write
