import {
	ICredentialType,
	INodeProperties,
	IAuthenticateGeneric,
	ICredentialTestRequest,
} from 'n8n-workflow';

export class PrismaAIRSApi implements ICredentialType {
	name = 'prismaAIRSApi';
	displayName = 'Prisma AIRS API';
	documentationUrl = 'https://pan.dev/prisma-airs/scan/api/';

	properties: INodeProperties[] = [
		{
			displayName: 'Prisma AIRS URL',
			name: 'host',
			type: 'string',
			default: 'https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request',
			description: 'The base URL for your Langfuse instance',
		},
		{
			displayName: 'Public Key',
			name: 'publicKey',
			type: 'string',
			typeOptions: { password: true },
			required: true,
			default: '',
			description: 'Prisma AIRS public API key (used as username for Basic Auth)',
		},
		{
			displayName: 'Secret Key',
			name: 'secretKey',
			type: 'string',
			typeOptions: {
				password: true,
			},
			required: true,
			default: '',
			description: 'Prisma AIRS secret API key (used as password for Basic Auth)',
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			auth: {
				username: '={{$credentials.publicKey}}',
				password: '={{$credentials.secretKey}}',
			},
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.host}}',
			url: '/api/public/projects',
			method: 'GET',
		},
	};
}
