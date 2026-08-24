# 01 — Environment Foundation

## Objective

Build a secure Azure environment that can host Windows and Linux systems and later support centralized security telemetry collection and investigation.

## Architecture

Microsoft Entra Tenant
        |
Azure Subscription
        |
Resource Group
        |
Virtual Network
        |
Subnets
        |
Network Security Groups
        |
Azure Bastion
        |
Windows VM + Linux VM
## 1. Microsoft Entra Tenant

### Purpose
A Microsoft Entra tenant is an organization's identity boundary in Microsoft's cloud. It provides the environment where users, groups, applications, identities, and security and access settings are managed.

### What I Configured
I used my Microsoft Entra tenant as the identity boundary for the lab environment. The Azure subscription was associated with this tenant, allowing identities and access permissions within the tenant to be used to manage the Azure resources I deployed.

### Why It Matters
The tenant establishes who can authenticate and provides the identity foundation for controlling access to Azure resources. This becomes important later when applying RBAC, least privilege, and other identity-based security controls.

## 2. Azure Subscription

### Purpose
An Azure subscription provides the billing and resource management boundary where Azure resources are created, organized, managed, and billed.

### What I Configured
I used my Azure subscription as the scope for building the lab environment. Within the subscription, I created Resource Groups, configured networking, deployed Windows and Linux virtual machines, and later connected the environment to Log Analytics for centralized monitoring.

### Why It Matters
Subscriptions allow organizations to separate costs, ownership, access, and operational responsibility across different environments or business units. This makes budgeting, security controls, access management, and day-to-day administration easier to manage as an Azure environment grows.
