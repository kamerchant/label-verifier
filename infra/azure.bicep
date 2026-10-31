@description('Azure region for the application and database.')
param location string = resourceGroup().location

@secure()
@minLength(12)
param postgresAdminPassword string

@secure()
@minLength(32)
param sessionSecret string

@description('PostgreSQL SKU name, for example Standard_B1ms or Standard_D2ds_v4.')
param postgresSkuName string = 'Standard_B1ms'

@allowed([
  'Burstable'
  'GeneralPurpose'
  'MemoryOptimized'
])
param postgresSkuTier string = 'Burstable'

@description('App Service plan SKU. Must support VNet integration (Basic or higher), for example B1, S1 or P0v3.')
param appPlanSku string = 'B1'

var suffix = uniqueString(subscription().id, resourceGroup().id)
var appName = 'label-qc-${suffix}'
var registryName = 'labelqc${suffix}'
var postgresServerName = 'label-qc-${suffix}'
var postgresAdmin = 'labeladmin'
var postgresDatabase = 'labelqc'
var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
var vnetName = 'label-qc-vnet'
var appSubnetName = 'app-integration'
var postgresSubnetName = 'postgres'
var privateDnsZoneName = 'private.postgres.database.azure.com'

resource vnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.20.0.0/16'
      ]
    }
    subnets: [
      {
        name: appSubnetName
        properties: {
          addressPrefix: '10.20.0.0/24'
          delegations: [
            {
              name: 'appServiceDelegation'
              properties: {
                serviceName: 'Microsoft.Web/serverFarms'
              }
            }
          ]
        }
      }
      {
        name: 'tools'
        properties: {
          addressPrefix: '10.20.2.0/24'
          delegations: [
            {
              name: 'containerInstanceDelegation'
              properties: {
                serviceName: 'Microsoft.ContainerInstance/containerGroups'
              }
            }
          ]
        }
      }
      {
        name: postgresSubnetName
        properties: {
          addressPrefix: '10.20.1.0/24'
          delegations: [
            {
              name: 'postgresDelegation'
              properties: {
                serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers'
              }
            }
          ]
        }
      }
    ]
  }
}

resource appSubnet 'Microsoft.Network/virtualNetworks/subnets@2023-09-01' existing = {
  parent: vnet
  name: appSubnetName
}

resource postgresSubnet 'Microsoft.Network/virtualNetworks/subnets@2023-09-01' existing = {
  parent: vnet
  name: postgresSubnetName
}

resource privateDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: privateDnsZoneName
  location: 'global'
}

resource privateDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: privateDnsZone
  name: 'label-qc-vnet-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2023-12-01-preview' = {
  name: postgresServerName
  location: location
  sku: {
    name: postgresSkuName
    tier: postgresSkuTier
  }
  properties: {
    version: '16'
    administratorLogin: postgresAdmin
    administratorLoginPassword: postgresAdminPassword
    storage: {
      storageSizeGB: 32
    }
    backup: {
      backupRetentionDays: 7
      geoRedundantBackup: 'Disabled'
    }
    network: {
      delegatedSubnetResourceId: postgresSubnet.id
      privateDnsZoneArmResourceId: privateDnsZone.id
      publicNetworkAccess: 'Disabled'
    }
  }
  dependsOn: [
    privateDnsLink
  ]
}

resource database 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2023-12-01-preview' = {
  parent: postgres
  name: postgresDatabase
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
}

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: registryName
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
  }
}

resource appPlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: 'label-qc-plan-${suffix}'
  location: location
  kind: 'linux'
  properties: {
    reserved: true
  }
  sku: {
    name: appPlanSku
    capacity: 1
  }
}

resource app 'Microsoft.Web/sites@2023-12-01' = {
  name: appName
  location: location
  kind: 'app,linux,container'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appPlan.id
    virtualNetworkSubnetId: appSubnet.id
    httpsOnly: true
    siteConfig: {
      alwaysOn: true
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      http20Enabled: true
      healthCheckPath: '/healthz'
      acrUseManagedIdentityCreds: true
      linuxFxVersion: 'DOCKER|${acr.properties.loginServer}/label-verifier:latest'
      appSettings: [
        {
          name: 'PORT'
          value: '8000'
        }
        {
          name: 'WEBSITES_PORT'
          value: '8000'
        }
        {
          name: 'WEBSITE_VNET_ROUTE_ALL'
          value: '1'
        }
        {
          name: 'WEBSITES_ENABLE_APP_SERVICE_STORAGE'
          value: 'false'
        }
        {
          name: 'DATABASE_URL'
          value: 'postgresql://${postgresAdmin}:${uriComponent(postgresAdminPassword)}@${postgres.properties.fullyQualifiedDomainName}:5432/${postgresDatabase}?sslmode=require'
        }
        {
          name: 'SESSION_SECRET'
          value: sessionSecret
        }
        {
          name: 'SESSION_COOKIE_SECURE'
          value: 'true'
        }
        {
          name: 'MAX_UPLOAD_BYTES'
          value: '262144000'
        }
      ]
    }
  }
  dependsOn: [
    database
    privateDnsLink
  ]
}

resource acrPullRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, app.id, acrPullRoleId)
  scope: acr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: app.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

output appName string = app.name
output appUrl string = 'https://${app.properties.defaultHostName}'
output acrName string = acr.name
output postgresHost string = postgres.properties.fullyQualifiedDomainName
