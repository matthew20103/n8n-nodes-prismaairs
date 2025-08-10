# n8n-nodes-prismaairs

This is an n8n community node. It lets you use Prisma AIRS API Intercept in your n8n workflows.

[Prisma AIRS](https://pan.dev/airs/) AI Runtime: API Intercept is Palo Alto Networks’ API for securing AI applications, AI models, AI data, and AI agents. Instantly protect your models from prompt injection, data leaks, and unsafe outputs—so you can build and deploy AI with confidence.

[n8n](https://n8n.io/) is a [fair-code licensed](https://docs.n8n.io/reference/license/) workflow automation platform.

[Installation](#installation)  
[Operations](#operations)  
[Credentials](#credentials)
[Development](#development)  
[Resources](#resources)

## Installation

### Self-hosted n8n

Follow the [installation guide](https://docs.n8n.io/integrations/community-nodes/installation/) in the n8n community nodes documentation.

```bash
npm install @prismaairs/n8n-nodes-prismaairs
```

### n8n Cloud

This is a verified community node. Search for `Prisma AIRS` to use this node in n8n Cloud.

## Operations

### Get Prompt

This node can be used call the Prisma AIRS API Intercept for protection on prompt injection, AI Agent attacks, database security attack, Data Loss Prevention, Malicious Code generation, Malicious URLs prevention, and more. See [Prisma AIRS API Intercept](https://pan.dev/airs/).

Steps

1. Enter the `name` of the prompt
2. Enter the `label` that identifies the prompt version that you want to fetch. Defaults to "production".

_Example workflow that retrieves the system prompt for the agent from Langfuse:_

![n8n-changelog](https://github.com/matthew20103/n8n-nodes-prismaairs/blob/741c563d882af6f4b76f7ea78c02cbb81dd0ace5/Prisma%20AIRS%20n8n%20Sample.png)

## Credentials

To use this node, you need to authenticate with Prisma AIRS. You'll need:

1. A Prisma AIRS account, from [Strata Cloud Manager](https://stratacloudmanager.paloaltonetworks.com/).
2. API credentials from your Prisma AIRS project settings: API key.

## Development

### Prerequisites

You need the following installed on your development machine:

- [git](https://git-scm.com/downloads)
- Node.js and npm. Minimum version Node 20. You can find instructions on how to install both using nvm (Node Version Manager) for Linux, Mac, and WSL [here](https://github.com/nvm-sh/nvm). For Windows users, refer to Microsoft's guide to [Install NodeJS on Windows](https://docs.microsoft.com/en-us/windows/dev-environment/javascript/nodejs-on-windows).
- Install n8n with:
  ```
  npm install n8n -g
  ```
- Recommended: follow n8n's guide to [set up your development environment](https://docs.n8n.io/integrations/creating-nodes/build/node-development-environment/).

### Build new version

```bash
npm run build
npm link
```

### Test in local n8n

```bash
cd ~/.n8n/custom
npm link n8n-nodes-prismaairs
```

## Resources

- [n8n community nodes documentation](https://docs.n8n.io/integrations/#community-nodes)
- [Prisma AIRS documentation](https://pan.dev/airs/)
- [Prisma AIRS API Intercept](https://pan.dev/prisma-airs/scan/api/)

## License

[MIT](https://github.com/langfuse/n8n-nodes-langfuse/blob/master/LICENSE.md)
