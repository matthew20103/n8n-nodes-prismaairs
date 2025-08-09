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
			default: 'https://service.api.aisecurity.paloaltonetworks.com/v1/scan',
			description: 'The base URL for your Prisma AIRS API Intercept',
		},
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: {
				password: true,
			},
			required: true,
			default: '',
			description: 'Prisma AIRS secret API key',
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				'x-pan-token': '={{$credentials.apiKey}}',
			},
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.host}}',
			url: '/results?scan_ids=020e7c31-0000-4e0d-a2a6-215a0d5c56d9',
			method: 'GET',
		},
	};
}
