# CERT Orange Cyberdefense connector for Cortex XSOAR/XSIAM

This repository is a fork of the official [Palo Alto Networks Cortex XSOAR/XSIAM repository ](https://github.com/demisto/content).

- For general documentation about Cortex XSOAR and XSIAM, please refer to the official documentation: https://docs-cortex.paloaltonetworks.com.

- For specific documentation about our connector, continue to read this document.

## Connector

This Datalake connector takes the form of what Cortex calls a "Content Pack", which is a package format that can contain custom fields for incidents and indicators, commands, layouts, playbooks, etc.

**⚠️ Previous versions of this connector took the form of standalone integrations that could be imported with a single yaml file and edited directly on the platform. The Content Pack format is a little different.**

### Content

We maintain the code and provide support for the Orange Cyberdefense content pack. It contains:
- An **integration** that provides commands allowing seamless integration with Orange Cyberdefense Datalake
- Some **Indicator fields** that can contain Datalake specific data
- Some **Indicator layouts** that you might use directly, or as a basis for your own custom layouts

### Supported indicators

As of now, the following indicators are supported:
  - Domain: Look up in Datalake using `!domain`
  - Email: Look up in Datalake using `!email`
  - File: Look up in Datalake using `!file`
  - IP: Look up in Datalake using `!ip`
  - URL: Look up in Datalake using `!url`

## How is this repository organized

- The branch `main` contains this documentation.
- The branch `demisto/content/master` contains a copy of the master branch from the official repository.
- The [GitHub release page](https://github.com/cert-orangecyberdefense/datalake2paloaltocortex/releases) contains builds of this connector. This is what you should download and install.

## Installation

### 1. Getting the Content Pack

Go to the [GitHub release page](https://github.com/cert-orangecyberdefense/datalake2paloaltocortex/releases). Download the latest stable version.

### 2. Installation
#### 2.1. Install using the marketplace (XSOAR and XSIAM)

_Not yet available, but we're working on it ;)_

#### 2.2. Install using the web interface (XSOAR only)

You have to upload the content pack zip file to your XSOAR instance. You can do so from "Marketplace" > _Click on the tree vertical dots in the top right corner_ > "Upload Content Packs"

#### 2.3. Install using the CLI (XSOAR and XSIAM)

This method is using the CLI tool [demisto-sdk](https://github.com/demisto/demisto-sdk). It requires python3 and may be installed using the following command:

```bash
pip install --user demisto-sdk
```

##### 2.3.1. CLI install for XSOAR

Use the following to deploy the Content Pack to an XSOAR instance:

```bash
export DEMISTO_BASE_URL=<XSOAR instance URL>
export DEMISTO_API_KEY=<XSOAR API Key>
demisto-sdk upload -i OrangeCyberdefense.zip
```

You may also add the `--insecure` option if you wish to skip SSL/TLS certificate validation.

##### 2.3.2. CLI install for XSIAM

1. Log in to XSIAM as admin.
2. Go to "Settings" > "Configurations" > "Integrations" > "API Keys".
3. Click on the "Copy API URL" button in the top right corner. Use the value for `DEMISTO_BASE_URL`.
4. Click on "Create an API Key" to create a new API key with "Security Level" set to "Standard" and role set to "Instance Administrator". Note down the key, you will use its value for  `DEMISTO_API_KEY`.
5. Go back to the listing page. You should now see your API key. Write down the ID corresponding to it. Use the value for `XSIAM_AUTH_ID`.

In the case of XSIAM, you cannot use the URL from the GUI. It must be retrieved from "Settings" > "Configurations" > "Integrations" > "API Keys" > "Copy URL" button in the top right corner. There is also an additional parameter: `XSIAM_AUTH_ID`. It's value should be set to the API key itself.

Use the following to deploy the Content Pack to an XSIAM instance:

```bash
export DEMISTO_BASE_URL=<XSIAM instance URL>
export DEMISTO_API_KEY=<XSIAM API Key>
export XSIAM_AUTH_ID=<XSIAM API Key ID>
demisto-sdk upload --xsiam -i OrangeCyberdefense.zip
```

You may also add the `--insecure` option if you wish to skip SSL/TLS certificate validation.

### 3. Configure your integration instance

Once the Content Pack is installed, you still need to create a new instance for the integration. The sections below give configuration instructions and explain most of the parameters.

In addition to lookup commands, Orange Cyberdefense Datalake integration can be configured to import indicators automatically at regular intervals. The required parameters for this use case are explained in [this section below](#34-automatic-import-parameters). You can ignore them otherwise.

#### 3.1. Configure integration in XSOAR

1. Go to "Settings" > "Integrations". You should see the newly created Orange Cyberdefense integration here.
2. Click on "Add instance", then configure it with parameters as explained below.

#### 3.2. Configure integration in XSIAM

1. Go to "Settings" > "Configurations" > "Data collection" > "Data sources & Integrations". You should see the newly created Orange Cyberdefense integration here.
2. Click on "Add instance".

#### 3.3. Common parameters

| Parameter                            | Description |
|--------------------------------------|-------------|
| `Fetches indicators / Do not fetch`  | Enable `Fetches indicators` to enable automatic import of indicators. In this case, [read this section below](#34-automatic-import-parameters). |
| `Datalake Environment`               | Datalake environment to use: `prod` or `preprod`. |
| `Datalake Long Term Token`           | Datalake API "long term" token. You can get one from [your Datalake account](https://datalake.cert.orangecyberdefense.com/gui/my-account). |
| `Trust any certificate (not secure)` | _Keep the default (disabled) unless you know what you're doing._ |
| `Use system proxy settings`          | _Keep the default (disabled) unless you know what you're doing._ |
| `Threshold Suspicious`               | When creating an indicator, set it to "suspicious" when the maximum score is above this threshold. |
| `Threshold Malicious`                | When creating an indicator, set it to "malicious" when the maximum score is above this threshold. |

#### 3.4. Automatic import parameters

| Parameter                            | Description |
|--------------------------------------|-------------|
| `Datalake queries`                   | List of Datalake query hashes of indicators you want to ingest. Must be formatted in JSON. |
| `Feed Fetch Interval`                | How often Datalake indicators should be retrieved. |
| `Fetch Lookback`                     | Additional filter which is added to Datalake queries: How far back in time (in minutes) it should retrieve indicators. |
| `Indicator Expiration Method`        | How long to retain the indicator. Defaults to the system settings for this indicator type. |
| `Indicator Reputation`               | When creating an indicator, set it to this value, ignoring the "suspicious" and "malicious" thresholds described above. |
| `Source reliability`                 | Reliability of the source (Datalake) providing the data. By default, selected level is `F - Reliability cannot be judged` but we encourage you to set it higher. |

### 4. (Optional) Define indicator layouts

This content pack adds indicator fields to the indicator object model. However, in order to see them on the GUI, they have to be used as on the layout used by indicators.

We provide basic layouts with those fields. Below are instructions on how to use them, but you might as well create your own, especially if you have specific needs.

#### 4.1. Using the Datalake indicator layout in XSOAR

1. Go to "Settings" > "Objects setup" > "Indicators" > "Types".
2. For each of the supported indicator type, select the Datalake template for this indicator type, such as `Domain Indicator - Datalake template` (or your own custom layout).

#### 4.2. Using the Datalake indicator layout in XSIAM

1. Go to "Settings" > "Configurations" > "Object Setup" > "Indicators".
2. For each of the supported indicator type, select the Datalake template for this indicator type, such as `Domain Indicator - Datalake template` (or your own custom layout).